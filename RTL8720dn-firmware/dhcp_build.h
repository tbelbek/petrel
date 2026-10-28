// Pure DHCP OFFER/ACK builder with RFC 8910 option 114 (Captive-Portal URI).
// No lwip / platform deps on purpose, so it can be unit-tested on the host.
// Builds a reply into a flat buffer; the lwip wrapper (dhcp_captive.cpp) just
// moves bytes onto a pbuf and broadcasts it.
#ifndef DHCP_BUILD_H
#define DHCP_BUILD_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define DHCP_FIXED_LEN 236      /* BOOTP header before the magic cookie */
#define DHCP_MIN_REPLY 300      /* pad short replies; some clients expect >= 300B */

/* AP network — must match WiFi.config() in the sketch and petrel's dhcpServer.
   Dedicated captive-portal subnet 192.168.4.0/24, NOT 192.168.1.x, so it never
   collides with a typical home LAN (which breaks dual-homed clients and testing). */
static const uint8_t DHCP_AP_IP[4]   = {192, 168, 4, 1};
static const uint8_t DHCP_AP_MASK[4] = {255, 255, 255, 0};
static const uint8_t DHCP_MAGIC[4]   = {99, 130, 83, 99};
/* Option 114 is filled at runtime from the sketch (a host derived from the AP name,
   e.g. http://freewifi.com/cp.json) so the portal URL is a name, not an IP. */

/* Find a DHCP option by code in the options area; returns value ptr or NULL. */
static inline const uint8_t *dhcp_find_opt(const uint8_t *req, size_t len,
                                           uint8_t code, uint8_t *out_len) {
    size_t i = DHCP_FIXED_LEN + 4; /* skip fixed header + magic cookie */
    while (i + 2 <= len) {
        uint8_t c = req[i];
        if (c == 255) break;        /* END */
        if (c == 0) { i++; continue; } /* PAD */
        uint8_t l = req[i + 1];
        if (i + 2 + l > len) break;
        if (c == code) { if (out_len) *out_len = l; return &req[i + 2]; }
        i += 2 + l;
    }
    return NULL;
}

/* Build an OFFER (for DISCOVER) or ACK (for REQUEST). Returns reply length, or 0 to ignore.
   cp_uri = the RFC 8910 option-114 captive-portal URL (advertised to the client).
   host = the last octet to hand out (100..200). The caller owns the lease table, so two clients
   whose MACs share a last byte no longer get the same address. */
static inline size_t dhcp_build_reply(uint8_t *out, size_t cap,
                                      const uint8_t *req, size_t req_len,
                                      const char *cp_uri, uint8_t host) {
    if (req_len < DHCP_FIXED_LEN + 4 || cap < DHCP_MIN_REPLY) return 0;
    if (memcmp(req + DHCP_FIXED_LEN, DHCP_MAGIC, 4) != 0) return 0;

    uint8_t mlen = 0;
    const uint8_t *mt = dhcp_find_opt(req, req_len, 53 /* msg type */, &mlen);
    if (!mt || mlen < 1) return 0;
    uint8_t reply_type;
    if (mt[0] == 1)      reply_type = 2; /* DISCOVER -> OFFER */
    else if (mt[0] == 3) reply_type = 5; /* REQUEST  -> ACK   */
    else return 0;

    memset(out, 0, DHCP_FIXED_LEN + 4);
    out[0] = 2;                 /* op = BOOTREPLY */
    out[1] = req[1];            /* htype */
    out[2] = req[2];            /* hlen  */
    memcpy(out + 4, req + 4, 4);    /* xid (echo) */
    out[10] = req[10];              /* flags (echo broadcast bit) */
    out[11] = req[11];
    out[16] = DHCP_AP_IP[0];        /* yiaddr = 192.168.1.(100..200), stateless per-MAC */
    out[17] = DHCP_AP_IP[1];
    out[18] = DHCP_AP_IP[2];
    out[19] = host;                 /* yiaddr host part, from the caller's lease table */
    memcpy(out + 20, DHCP_AP_IP, 4);   /* siaddr */
    memcpy(out + 28, req + 28, 16);    /* chaddr (echo) */
    memcpy(out + DHCP_FIXED_LEN, DHCP_MAGIC, 4);

    uint8_t *o = out + DHCP_FIXED_LEN + 4;
    *o++ = 53; *o++ = 1; *o++ = reply_type;                 /* msg type */
    *o++ = 54; *o++ = 4; memcpy(o, DHCP_AP_IP, 4);   o += 4; /* server id */
    *o++ = 51; *o++ = 4; *o++ = 0; *o++ = 1; *o++ = 0x51; *o++ = 0x80; /* lease 86400s */
    *o++ = 1;  *o++ = 4; memcpy(o, DHCP_AP_MASK, 4); o += 4; /* subnet mask */
    *o++ = 3;  *o++ = 4; memcpy(o, DHCP_AP_IP, 4);   o += 4; /* router */
    *o++ = 6;  *o++ = 4; memcpy(o, DHCP_AP_IP, 4);   o += 4; /* DNS = AP (keeps DNS hijack alive) */
    {
        size_t ul = strlen(cp_uri);                          /* option 114, RFC 8910 */
        if (ul > 255) ul = 255;
        *o++ = 114; *o++ = (uint8_t)ul; memcpy(o, cp_uri, ul); o += ul;
    }
    *o++ = 255;                                             /* END */

    size_t len = (size_t)(o - out);
    if (len < DHCP_MIN_REPLY) { memset(o, 0, DHCP_MIN_REPLY - len); len = DHCP_MIN_REPLY; }
    return len;
}

#endif /* DHCP_BUILD_H */
