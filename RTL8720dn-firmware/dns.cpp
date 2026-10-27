#include "dns.h"
#include "lwip_log.h"
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
        DNSHeader dnsHeader;
        DNSQuestion dnsQuestion;
        int sizeUrl;

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
            sizeUrl = static_cast<int>(dnsQuestion.QNameLength);
            
            /*
                check if we aint going out of pkt bounds
                proper dns req should have label terminator at least 4 bytes before end of packet
              */
            if (dnsQuestion.QNameLength > udp_packet_buffer->len - DNS_HEADER_SIZE - sizeof(dnsQuestion.QType) - sizeof(dnsQuestion.QClass)) {
              pbuf_free(udp_packet_buffer);
              return;  // malformed packet
            }         
            memcpy(&dnsQuestion.QType, enoflbls, sizeof(dnsQuestion.QType));
            memcpy(&dnsQuestion.QClass, enoflbls + sizeof(dnsQuestion.QType), sizeof(dnsQuestion.QClass));
        }
        if (dnsHeader.OPCode == DNS_OPCODE_QUERY && requestIncludesOnlyOneQuestion(dnsHeader)){
            struct dns_hdr *q = (struct dns_hdr*) udp_packet_buffer->payload;

            // Log the name we're hijacking (labels -> dotted) so the serial log shows
            // whether the client's lookups actually reach us.
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
            const uint16_t qtype = dnsQuestion.QType;
            // A (1) -> 4-byte IPv4. AAAA (28) -> IPv4-mapped IPv6 (::ffff:a.b.c.d, 16 bytes) so
            // v6-preferring clients still resolve. Anything else -> no answer, question echoed.
            const bool ans_a    = (qtype == 1);
            const bool ans_aaaa = (qtype == 28);
            const uint16_t rdlen = ans_a ? 4 : (ans_aaaa ? 16 : 0);
            const uint16_t ancount = (ans_a || ans_aaaa) ? 1 : 0;

            // Reservamos espacio para el DNS response (Header + Question + Answer)
            struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dns_hdr) + questionSectionSize + 32, PBUF_RAM);

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
                      questionSectionSize);

                if (ancount) {
                  // Construcción de la sección de respuesta
                  uint8_t *answer_ptr = (uint8_t *)rsp_hdr + sizeof(struct dns_hdr) + questionSectionSize;

                  // Nombre del dominio (compresión, apuntando a QName en offset 12)
                  answer_ptr[0] = 0xC0;
                  answer_ptr[1] = 0x0C;

                  // Tipo: echo the question's own type (A or AAAA)
                  *(uint16_t *)(answer_ptr + 2) = PP_HTONS(qtype);

                  // Clase IN
                  *(uint16_t *)(answer_ptr + 4) = PP_HTONS(1);

                  // TTL (0 segundos)
                  *(uint32_t *)(answer_ptr + 6) = PP_HTONL(0);

                  // Longitud de datos
                  *(uint16_t *)(answer_ptr + 10) = PP_HTONS(rdlen);

                  if (ans_a) {
                    // Dirección IP a retornar (ej. dhcpServer contiene el puntero al uint8_t[4])
                    memcpy(answer_ptr + 12, (void *)dhcpServer, 4);
                  } else {
                    // ::ffff:a.b.c.d
                    memset(answer_ptr + 12, 0, 10);
                    answer_ptr[22] = 0xFF; answer_ptr[23] = 0xFF;
                    memcpy(answer_ptr + 24, (void *)dhcpServer, 4);
                  }
                }

                // Enviar respuesta
                udp_sendto(udp_pcb, p, sender_addr, sender_port);
                
            }
            pbuf_free(p);
        }
        //}       
        else {
                struct dns_hdr *dns_rsp;
                dns_rsp = (struct dns_hdr*) udp_packet_buffer->payload;

                dns_rsp->flags1 |= 0x80; // 0x80 : Response;
                dns_rsp->flags2 = 0x05;  //0x05 : Reply code (Query Refused)

                udp_sendto(udp_pcb, udp_packet_buffer, sender_addr, sender_port);
        }

        /* free the UDP connection, so we can accept new clients */
        udp_disconnect(udp_pcb);

        /* Free the packet buffer */
        pbuf_free(udp_packet_buffer);
}
static struct udp_pcb *dns_server_pcb;

void unbind_all_udp(){
  // Grab ->next BEFORE udp_remove(): the removed pcb is freed, so "pcb = pcb->next" walked freed
  // memory (use-after-free). Same fix as unbind_dns() below.
  struct udp_pcb *pcb = udp_pcbs;
  while (pcb != NULL) {
      struct udp_pcb *next = pcb->next;
      udp_remove(pcb);
      pcb = next;
  }
}

void unbind_dns(){
  // Remove every pcb bound to :53. Grab ->next BEFORE udp_remove(): the removed pcb is
  // freed, so the old "pcb = pcb->next" walked freed memory (use-after-free).
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

bool start_DNS_Server()
{
  if (dns_server_pcb) return true;

  dns_server_pcb = udp_new();
  if (!dns_server_pcb) return false;

  if (udp_bind(dns_server_pcb, IP4_ADDR_ANY, DNS_SERVER_PORT) != ERR_OK) {
    udp_remove(dns_server_pcb);
    dns_server_pcb = NULL;
    return false;
  }

  udp_recv(dns_server_pcb,
           (udp_recv_fn)dnss_receive_udp_packet_handler, NULL);
  return true;
}
