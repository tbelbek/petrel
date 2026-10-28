#include "dns.h"
#include "lwip_log.h"
#include "lwip_call.h"
#include "dhcp_captive.h"
#include "sp_probe.h"
#include <lwip/netif.h>
extern "C" struct netif xnetif[];
extern int dhcp_captive_ap_ifindex(void);
volatile unsigned g_dns_stage = 0;
volatile unsigned g_dns_sz = 0;
#define DNS_QR_RESPONSE        1

uint8_t dhcpServer[4]={192,168,4,1};

bool requestIncludesOnlyOneQuestion(DNSHeader &dnsHeader) {
  // Accept EDNS: modern resolvers attach an OPT record in the additional section
  // (ARCount>=1). Requiring ARCount==0 made us REFUSE those queries, breaking the
  // DNS hijack for most real clients. Only require a single question, no answers.
  return ntohs(dnsHeader.QDCount) == 1 && dnsHeader.ANCount == 0 && dnsHeader.NSCount == 0;
}


static void dnss_receive_udp_packet_handler(
  
        void *arg,
        struct udp_pcb *udp_pcb,
        struct pbuf *udp_packet_buffer,
        struct ip_addr *sender_addr,
        uint16_t sender_port) 
{     
        /* To avoid gcc warnings */
        ( void ) arg;
        sp_note();
        __atomic_store_n(&g_dns_stage, 20u, __ATOMIC_RELAXED);
        DNSHeader dnsHeader;
        DNSQuestion dnsQuestion;

        if (udp_packet_buffer->len < DNS_HEADER_SIZE) {   // truncated header: memcpy below would over-read
          pbuf_free(udp_packet_buffer);
          return;
        }
        memcpy(&dnsHeader, udp_packet_buffer->payload, DNS_HEADER_SIZE);
        if (dnsHeader.QR != DNS_QR_QUERY) {
          pbuf_free(udp_packet_buffer);
          return;  // ignore non-query messages
        }

        
        if (requestIncludesOnlyOneQuestion(dnsHeader)) {
            /*
              // The QName has a variable length, maximum 255 bytes and is comprised of multiple labels.
              // Each label contains a byte to describe its length and the label itself. The list of
              // labels terminates with a zero-valued byte. In "github.com", we have two labels "github" & "com"
        */
            const char *qstart = reinterpret_cast<const char *>(udp_packet_buffer->payload) + DNS_HEADER_SIZE;
            // memchr, not strchr: the pbuf payload is not NUL-terminated, so strchr could walk past
            // the packet. No terminator -> malformed, and the old code then did pointer math on NULL.
            const char *enoflbls = reinterpret_cast<const char *>(
                memchr(qstart, 0, udp_packet_buffer->len - DNS_HEADER_SIZE));
            if (!enoflbls) {
              pbuf_free(udp_packet_buffer);
              return;  // no end_of_label marker
            }
            ++enoflbls;                                                                                      // advance after null terminator
            dnsQuestion.QName = (uint8_t *)udp_packet_buffer->payload + DNS_HEADER_SIZE;                                                // we can reference labels from the request
            dnsQuestion.QNameLength = enoflbls - qstart;
            
            /*
                check if we aint going out of pkt bounds
                proper dns req should have label terminator at least 4 bytes before end of packet.
                Compare against an int: the unsigned subtraction underflows on a 13-15 byte packet.
              */
            const int avail = (int)udp_packet_buffer->len - DNS_HEADER_SIZE;
            if (avail < 4 || dnsQuestion.QNameLength + 4 > avail) {
              pbuf_free(udp_packet_buffer);
              return;  // malformed packet
            }
            memcpy(&dnsQuestion.QType, enoflbls, sizeof(dnsQuestion.QType));
            memcpy(&dnsQuestion.QClass, enoflbls + sizeof(dnsQuestion.QType), sizeof(dnsQuestion.QClass));
        }
        if (dnsHeader.OPCode == DNS_OPCODE_QUERY && requestIncludesOnlyOneQuestion(dnsHeader)){
            // Log the name we're hijacking (labels -> dotted) so the serial log shows whether the
            // client's lookups actually reach us. SP sampling showed the tcpip stack is not tight
            // (~400 B deep), so the original 80/96-byte buffers and snprintf are safe here.
            {
              char nm[80]; int qo = 0, k = 0;
              while (k < (int)dnsQuestion.QNameLength && qo < 78) {
                uint8_t L = dnsQuestion.QName[k++];
                if (L == 0) break;
                for (uint8_t j = 0; j < L && k < (int)dnsQuestion.QNameLength && qo < 78; j++)
                  nm[qo++] = (char)dnsQuestion.QName[k++];
                nm[qo++] = '.';
              }
              nm[qo] = 0;
              {   // tcpip thread: defer the UART write to loop()
                char lb[96];
                snprintf(lb, sizeof(lb), "DNS: \"%s\" qtype=%u -> 192.168.4.1", nm, dnsQuestion.QType);
                lwip_log(lb);
              }
            }

            int questionSectionSize = dnsQuestion.QNameLength + sizeof(uint16_t) + sizeof(uint16_t);  // QName + QType + QClass
            const uint16_t qtype = ntohs(dnsQuestion.QType);   // wire order -> host order
            // A (1) -> 4-byte IPv4. AAAA (28) -> IPv4-mapped IPv6 (::ffff:a.b.c.d, 16 bytes) so
            // v6-preferring clients still resolve. Anything else -> no answer, question echoed.
            const bool ans_a    = (qtype == 1);
            const bool ans_aaaa = (qtype == 28);
            const uint16_t rdlen = ans_a ? 4 : (ans_aaaa ? 16 : 0);
            const uint16_t ancount = (ans_a || ans_aaaa) ? 1 : 0;

            // Exact size: header + question + answer (name 2 + type 2 + class 2 + ttl 4 + rdlen 2
            // + rdata). The old "+32" reservation was transmitted in full, leaking heap bytes past
            // the last answer field.
            const size_t answerSize = ancount ? (size_t)(12 + rdlen) : 0;
            __atomic_store_n(&g_dns_stage, 21u, __ATOMIC_RELAXED);
            const unsigned alloc_sz = (unsigned)(sizeof(struct dns_hdr) + questionSectionSize + answerSize);
            {   // record the requested size: a bogus size is the difference between "NULL" and "hang"
              char sb[16]; int sn = 0; unsigned v = alloc_sz;
              do { sb[sn++] = (char)('0' + v % 10); v /= 10; } while (v && sn < 12);
              sb[sn++] = 'S'; char ob[14]; int on = 0;
              while (sn) ob[on++] = sb[--sn];
              ob[on] = 0; (void)ob; g_dns_sz = alloc_sz;
            }
            struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)alloc_sz, PBUF_RAM);
            __atomic_store_n(&g_dns_stage, p ? 26u : 29u, __ATOMIC_RELAXED);

            if (p) {
                struct dns_hdr *rsp_hdr = (struct dns_hdr *)p->payload;
                struct dns_hdr *req_hdr = (struct dns_hdr *)udp_packet_buffer->payload;

                // Copiamos campos del header DNS
                rsp_hdr->id = req_hdr->id;
                rsp_hdr->flags1 = 0x85; // QR=1, AA=1, RD=1
                rsp_hdr->flags2 = 0x80; // RA=1
                rsp_hdr->numquestions = PP_HTONS(1);
                rsp_hdr->numanswers = PP_HTONS(ancount);
                rsp_hdr->numauthrr = PP_HTONS(0);
                rsp_hdr->numextrarr = PP_HTONS(0);

                // Copiamos la sección de pregunta desde el paquete original
                memcpy((uint8_t *)rsp_hdr + sizeof(struct dns_hdr),
                      (uint8_t *)udp_packet_buffer->payload + sizeof(struct dns_hdr),
                      questionSectionSize);   // question section copied

                if (ancount) {
                  // Construcción de la sección de respuesta
                  uint8_t *answer_ptr = (uint8_t *)rsp_hdr + sizeof(struct dns_hdr) + questionSectionSize;

                  // Nombre del dominio (compresión, apuntando a QName en offset 12)
                  answer_ptr[0] = 0xC0;
                  answer_ptr[1] = 0x0C;

                  // memcpy, not typed stores: the QNAME length makes these offsets unaligned.
                  uint16_t v16;
                  uint32_t v32;
                  v16 = PP_HTONS(qtype);  memcpy(answer_ptr + 2, &v16, 2);   // echo the question type
                  v16 = PP_HTONS(1);      memcpy(answer_ptr + 4, &v16, 2);   // class IN
                  v32 = PP_HTONL(0);      memcpy(answer_ptr + 6, &v32, 4);   // TTL 0
                  v16 = PP_HTONS(rdlen);  memcpy(answer_ptr + 10, &v16, 2);  // rdata length

                  if (ans_a) {
                    // Dirección IP a retornar (ej. dhcpServer contiene el puntero al uint8_t[4])
                    memcpy(answer_ptr + 12, (void *)dhcpServer, 4);
                  } else {
                    // ::ffff:a.b.c.d
                    memset(answer_ptr + 12, 0, 10);
                    answer_ptr[22] = 0xFF; answer_ptr[23] = 0xFF;
                    memcpy(answer_ptr + 24, (void *)dhcpServer, 4);
                  }
                }   // answer built
                // Enviar respuesta
                __atomic_store_n(&g_dns_stage, 22u, __ATOMIC_RELAXED);
                // 2026-10-28: udp_sendto() left the netif choice to the route table. The AP
                // netif is xnetif[ap_ifindex]; a reply routed to the idle STA netif goes through a
                // down interface. Send explicitly, exactly like the DHCP server does.
                __atomic_store_n(&g_dns_stage, 22u, __ATOMIC_RELAXED);
                udp_sendto_if(udp_pcb, p, sender_addr, sender_port, &xnetif[dhcp_captive_ap_ifindex()]);
                __atomic_store_n(&g_dns_stage, 23u, __ATOMIC_RELAXED);
                pbuf_free(p);
            }
        }
        //}       
        else {
                struct dns_hdr *dns_rsp;
                dns_rsp = (struct dns_hdr*) udp_packet_buffer->payload;

                dns_rsp->flags1 |= 0x80; // 0x80 : Response;
                dns_rsp->flags2 = 0x05;  //0x05 : Reply code (Query Refused)

                udp_sendto(udp_pcb, udp_packet_buffer, sender_addr, sender_port);
        }

        /* 2026-10-28: udp_disconnect() on the listening pcb was unnecessary - the pcb is bound,
           never connected, and keeps accepting either way. Removed to shrink the send path. */

        __atomic_store_n(&g_dns_stage, 24u, __ATOMIC_RELAXED);
        /* Free the packet buffer */
        pbuf_free(udp_packet_buffer);
        __atomic_store_n(&g_dns_stage, 25u, __ATOMIC_RELAXED);
}
static struct udp_pcb *dns_server_pcb;

static void unbind_all_udp_impl(void* ctx){
  // Grab ->next BEFORE udp_remove(): the removed pcb is freed, so "pcb = pcb->next" walked freed
  // memory (use-after-free). Same fix as unbind_dns() below.
  (void)ctx;
  struct udp_pcb *pcb = udp_pcbs;
  while (pcb != NULL) {
      struct udp_pcb *next = pcb->next;
      udp_remove(pcb);
      pcb = next;
  }
  // Every saved pointer is dangling now; a later stop/start would otherwise double-free.
  dns_server_pcb = NULL;
  dhcp_forget_pcbs();
}

void unbind_all_udp(){ lwip_call(unbind_all_udp_impl, NULL); }

static void unbind_dns_impl(void* ctx){
  // Remove every pcb bound to :53. Grab ->next BEFORE udp_remove(): the removed pcb is
  // freed, so the old "pcb = pcb->next" walked freed memory (use-after-free).
  (void)ctx;
  struct udp_pcb *pcb = udp_pcbs;
  while (pcb != NULL) {
    struct udp_pcb *next = pcb->next;
    if (pcb->local_port == DNS_SERVER_PORT) {
      udp_remove(pcb);
    }
    pcb = next;
  }
  dns_server_pcb = NULL;   // removed above; the saved pointer must not dangle
}

void unbind_dns(){ lwip_call(unbind_dns_impl, NULL); }

static void start_DNS_Server_impl(void* ctx)
{
  bool* ok = (bool*)ctx;
  *ok = false;
  if (dns_server_pcb) { *ok = true; return; }

  dns_server_pcb = udp_new();
  if (!dns_server_pcb) return;

  if (udp_bind(dns_server_pcb, IP4_ADDR_ANY, DNS_SERVER_PORT) != ERR_OK) {
    udp_remove(dns_server_pcb);
    dns_server_pcb = NULL;
    return;
  }

  udp_recv(dns_server_pcb,
           (udp_recv_fn)dnss_receive_udp_packet_handler, NULL);
  *ok = true;
}

// The raw udp_* calls must run in the tcpip thread (LWIP_TCPIP_CORE_LOCKING=0).
bool start_DNS_Server()
{
  bool ok = false;
  lwip_call(start_DNS_Server_impl, &ok);
  return ok;
}
