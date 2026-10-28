#include "web_lwip.h"
#include "sp_probe.h"
#include "petrel_http.h"
#include "lwip_log.h"   // pure predicates (host-tested in common/petrel_http_test.c)
#include <lwip/tcp.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>
#include <lwip/mem.h>
// Declared locally instead of including <lwip/tcpip.h>: that header pulls sys.h, whose sys_now()
// collides with the core's C-linkage declaration.
extern "C" {
typedef void (*web_tcpip_cb)(void* ctx);
err_t tcpip_callback_with_block(web_tcpip_cb function, void* ctx, u8_t block);
}
#include <string.h>
// Declared here instead of including <Arduino.h>: that header pulls WCharacter.h, which needs a
// ctype.h this toolchain's C++ wrapper does not provide in a plain .cpp TU.
extern "C" {
unsigned long millis(void);
void delay(unsigned long ms);
}

// Acquire/release accessors: volatile alone is not a C++ synchronization primitive on this
// weakly-ordered part, and a bare DMB does not make the accesses atomic.
#define WEB_LOAD(p)      __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define WEB_STORE(p, v)  __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define WEB_ADD(p, v)    __atomic_add_fetch((p), (v), __ATOMIC_RELAXED)
static bool web_cb_done;   // tcpip hand-off completion (see web_in_tcpip)
struct web_fn_arg { void (*fn)(const void*); const void* arg; };
static void web_apply_edits(void);

static struct tcp_pcb* web_listen = NULL;
static void (*web_render)(char*, size_t) = NULL;
static void (*web_rotate)(void) = NULL;
static web_resolve_fn web_resolve = NULL;
static unsigned g_sends = 0;   // responses currently streaming (their body pointer must stay valid)

// --- halt breadcrumbs (2026-10-28) ---------------------------------------------------------
// The board sometimes stops dead mid-request with the heap flat, so a leak/OOM is ruled out and
// the last thing it was doing is unknown. One relaxed store per stage (cheap, no allocation, no
// UART from the tcpip thread) is read from loop() 1x/s: the last printed stage is where it died.
// g_tick is bumped from a tcpip callback posted by loop(); if loop keeps printing but g_tick
// stops, the tcpip thread is the one that died (and vice versa).
volatile uint32_t g_sp_min = 0xFFFFFFFFu;
volatile uint32_t g_sp_base = 0;
volatile unsigned g_stage = 0;
volatile unsigned g_reqs = 0;
volatile unsigned g_tick = 0;
// 0 = both lwIP pcb lists are empty after the teardown (bit0 active, bit1 time-wait)
volatile unsigned g_pcb_state = 0;
extern "C" { extern struct tcp_pcb *tcp_active_pcbs; extern struct tcp_pcb *tcp_tw_pcbs; }

#define STAGE(n) __atomic_store_n(&g_stage, (unsigned)(n), __ATOMIC_RELAXED)

static void web_tick_cb(void* arg) { (void)arg;
    __atomic_store_n(&g_pcb_state,
        (unsigned)((tcp_active_pcbs == NULL ? 1u : 0u) | (tcp_tw_pcbs == NULL ? 2u : 0u)),
        __ATOMIC_RELAXED);
    g_sp_base = sp_read();          // baseline: same task, shallowest frame
    sp_note();
    __atomic_add_fetch(&g_tick, 1u, __ATOMIC_RELAXED); }
void web_lwip_diag_tick(void) { tcpip_callback_with_block(web_tick_cb, NULL, 0); }
unsigned web_lwip_stage(void) { return __atomic_load_n(&g_stage, __ATOMIC_RELAXED); }
unsigned web_lwip_reqs(void) { return __atomic_load_n(&g_reqs, __ATOMIC_RELAXED); }
unsigned web_lwip_ticks(void) { return __atomic_load_n(&g_tick, __ATOMIC_RELAXED); }
unsigned web_lwip_pcb_state(void) { return __atomic_load_n(&g_pcb_state, __ATOMIC_RELAXED); }

// Case-insensitive scan of "key=value&..." pairs with no libc calls (see STEP C).
static bool cred_query(const char* s) {
    static const char* keys[] = {"user","pass","pwd","email","mail","login","name",
                                 "username","password","userid","loginid"};
    while (*s) {
        const char* k = s;
        const char* eq = NULL;
        while (*s && *s != '&') { if (*s == '=' && !eq) eq = s; s++; }
        if (eq && eq > k) {
            size_t n = (size_t)(eq - k);
            for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
                size_t j = 0;
                while (j < n && keys[i][j]) {
                    char a = k[j];
                    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                    if (a != keys[i][j]) break;
                    j++;
                }
                if (j == n && keys[i][j] == 0) return true;
            }
        }
        if (*s == '&') s++;
    }
    return false;
}

// One record per accepted connection: it owns the optional send cursor and is the single tcp_arg,
// so tcp_err can always untrack even when no response has started yet. A stop aborts every record -
// closing the listener alone would leave connections running against state the next start resets.
#define WEB_CONNS 4
struct web_conn {
    struct tcp_pcb* pcb;
    struct web_send* ws;
    // 2026-10-28: the request line used to be copied out of the FIRST pbuf only, and the rest of
    // the chain was freed. When TCP delivered "GET /userinput?..." split across pbufs the query
    // silently vanished - the page was served, the submission was never captured. Same HTTP bytes
    // therefore behaved differently run to run. Accumulate here until the line is complete.
    char req[160];   // one request line; headers are never needed
    uint16_t req_len;
};
// 2026-10-28: these records used to be mem_malloc'd. Serving a portal page hard-locked the board
// right after web_finish(), and the fix has to be structural: a second free of the same record
// corrupts the lwIP heap and takes the whole board down (no UART, AP dead). Records now live in a
// static pool, so "freeing" one is just unlinking it - a duplicate free is a no-op instead of a
// use-after-free.
static struct web_conn g_conn_pool[WEB_CONNS];
static struct web_conn* g_conns[WEB_CONNS];

static struct web_conn* conn_add(struct tcp_pcb* p) {
    for (unsigned i = 0; i < WEB_CONNS; i++) {
        if (!g_conns[i]) {
            struct web_conn* c = &g_conn_pool[i];
            c->pcb = p; c->ws = NULL; c->req_len = 0; c->req[0] = 0;
            g_conns[i] = c;
            return c;
        }
    }
    return NULL;
}

static void conn_del(struct web_conn* c) {
    for (unsigned i = 0; i < WEB_CONNS; i++) if (g_conns[i] == c) g_conns[i] = NULL;
}

static void conn_free(struct web_conn* c) {
    if (!c) return;
    bool live = false;
    for (unsigned i = 0; i < WEB_CONNS; i++) if (g_conns[i] == c) { live = true; break; }
    if (!live) return;                       // already released: a second free is a no-op
    conn_del(c);
    if (c->ws) { mem_free(c->ws); c->ws = NULL; if (g_sends) g_sends--; }
}

static void web_abort_conns(void) {
    for (unsigned i = 0; i < WEB_CONNS; i++) {
        if (!g_conns[i]) continue;
        struct tcp_pcb* p = g_conns[i]->pcb;
        conn_free(g_conns[i]);
        tcp_arg(p, NULL);   // tcp_abort fires tcp_err; the record is already gone
        tcp_abort(p);
    }
    WEB_STORE(&g_sends, 0u);
    web_apply_edits();
}
static bool web_portal = false;
static bool web_probe_always204 = false;
void web_lwip_set_probe204(bool on) { web_probe_always204 = on; }

// Selected captive-portal page, set by web_lwip_start_portal(): the .ino resolves the chosen
// portal (Default/brand-gzip/Custom) and hands the bytes here. body==NULL falls back to the
// built-in generic sign-in page below. gzip blobs live in flash (immutable, safe to stream
// zero-copy); the custom buffer AND the Default page are mutable, so they are streamed with COPY
// so a mid-send PORTALHTML cannot corrupt the in-flight body (lwIP copies into pbufs as we chunk).
static const char* g_portal_body = NULL;
static int         g_portal_len  = 0;
static bool        g_portal_gzip = false;
static bool        g_portal_copy = false;

// Portal URLs, derived by the sketch from the AP SSID (build_portal_urls). The DNS hijack
// resolves the host to us, so the same host is used by DHCP option 114, the 302 and cp.json.
static char g_root[64] = "http://192.168.4.1/";

// Per-client captive state: once a client submits the portal form it is "authorized" and we answer
// ITS OS connectivity probes with 204 (No Content) so the "Connected, no internet" warning clears,
// and cp.json flips to captive:false. Un-authorized clients still get a 302 to the portal, so the
// sign-in keeps popping for new victims. Keyed on the peer IPv4 (tpcb->remote_ip).
static uint32_t g_authed[8];
static uint8_t  g_authed_n = 0;   // entries used, saturates at 8
static uint8_t  g_authed_next = 0; // eviction cursor (a real ring, not "always slot 0")

static bool ip_authed(uint32_t ip) {
    for (uint8_t i = 0; i < g_authed_n; i++) if (g_authed[i] == ip) return true;
    return false;
}

static void ip_mark_authed(uint32_t ip) {
    if (!ip || ip_authed(ip)) return;
    g_authed[g_authed_next] = ip;
    g_authed_next = (uint8_t)((g_authed_next + 1) % 8);
    if (g_authed_n < 8) g_authed_n++;
}

// Bounded credential ring (4 slots): web_recv runs in the tcpip thread and must NOT touch Serial1
// (two threads on one UART -> corruption; a blocking UART write stalls the stack). So it parks the
// captured query string here and loop() drains + prints EV: via web_lwip_poll_creds().
// SPSC: producer owns g_creds_tail, consumer owns g_creds_head; a DMB publishes the slot before the
// index (volatile alone is not enough on this weakly-ordered part).
#define CRED_SLOTS 4
#define CRED_LEN   80   // 2026-10-28: BSS is full; 80 still fits any real query string
static char     g_creds[CRED_SLOTS][CRED_LEN];
static unsigned g_creds_head = 0;   // consumer
static unsigned g_creds_tail = 0;   // producer
static unsigned g_creds_drop = 0;

static bool creds_push(const char* q) {
    unsigned t = WEB_LOAD(&g_creds_tail);
    unsigned h = WEB_LOAD(&g_creds_head);
    if ((t + 1) % CRED_SLOTS == h) { WEB_ADD(&g_creds_drop, 1u); return false; }
    size_t n = strlen(q);
    if (n > CRED_LEN - 1) n = CRED_LEN - 1;
    memcpy(g_creds[t], q, n);
    g_creds[t][n] = 0;
    WEB_STORE(&g_creds_tail, (t + 1) % CRED_SLOTS);   // release: slot visible before the index
    return true;
}


// Per-connection send cursor for the (possibly large, e.g. 39KB facebook) portal body: the body
// can exceed one tcp_sndbuf, so it is streamed across tcp_sent callbacks. Allocated in web_recv,
// freed on completion, on tcp_err, and on peer FIN (a victim that drops mid-send must not leak it).
struct web_send { const char* body; int len; int off; int acked; u8_t copy; void* conn; };

// Shared scratch for the WebUI page and the cp.json body (the two never run at the same time:
// WebUI mode and portal mode are mutually exclusive).
static char g_body[800];

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

static const char REDIRECT_HEAD[] =
    "HTTP/1.1 302 Found\r\nLocation: ";
static const char REDIRECT_TAIL[] = "\r\nConnection: close\r\n\r\n";

static const char NO_CONTENT_RESP[] =
    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nCache-Control: no-store\r\n"
    "Connection: close\r\n\r\n";

static err_t web_poll(void* arg, struct tcp_pcb* tpcb) {
    (void)arg; tcp_abort(tpcb); return ERR_ABRT;   // drop a stalled half-open connection
}

// tcp_close() can fail with ERR_MEM (it has to allocate a FIN). Retrying on the poll callback is the
// documented pattern; if it fails again the connection is aborted rather than left dangling.
static err_t web_poll_close(void* arg, struct tcp_pcb* tpcb) {
    STAGE(15);
    (void)arg;
    if (tcp_close(tpcb) == ERR_OK) return ERR_OK;
    tcp_abort(tpcb);
    return ERR_ABRT;
}

static void web_close(struct tcp_pcb* tpcb) {
    STAGE(11);
    // 2026-10-28: stage 11 is set BEFORE tcp_close(), so a halt at 11 cannot tell "inside
    // tcp_close" from "after it". Record the return: 13 = ERR_OK, 14 = failed.
    { err_t e = tcp_close(tpcb); STAGE(e == ERR_OK ? 13u : 14u); if (e == ERR_OK) return; }
    tcp_arg(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_err(tpcb, NULL);
    tcp_poll(tpcb, web_poll_close, 2 /* ~1s */);
}

// Build "HTTP/1.1 200 OK ... [Content-Encoding: gzip] Content-Length: <bl>\r\n\r\n" into hdr
// (manual itoa: this TU's snprintf is the reduced Realtek DiagSnPrintf that mangles %u). The
// Content-Length is the FULL body length even when the body is streamed across several writes.
static int http_hdr(char* hdr, size_t bl, bool gzip) {
    strcpy(hdr, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n");
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
static void web_finish(struct tcp_pcb* tpcb, struct web_conn* c) {
    STAGE(10);
    tcp_arg(tpcb, NULL);
    // 2026-10-28: tcp_recv was left installed. The argument was cleared, so the next segment (or
    // the peer's FIN) re-entered web_recv with arg==NULL, hit the p==NULL branch and closed the
    // already-closing pcb a second time - the board went silent for good. Detach every callback.
    tcp_recv(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_err(tpcb, NULL);
    // 2026-10-28: the 4 s abort poll stayed installed on a closing pcb, so it fired after the slot
    // had been released and reset a connection that was closing cleanly (delayed TCP abort, ~4-8 s
    // after the page was served). Drop it here; web_close() re-installs its own if close fails.
    tcp_poll(tpcb, NULL, 0);
    conn_free(c);
    if (WEB_LOAD(&g_sends) == 0) web_apply_edits();
    web_close(tpcb);
}

// Queue as much of the remaining body as tcp_sndbuf allows; the tcp_sent callback resumes this
// when the window drains. When the last byte is queued, close (lwIP flushes queued data before
// the FIN). Zero-copy for flash gzip blobs; COPY for the mutable buffers.
static err_t web_abort_done(struct tcp_pcb* tpcb, struct web_conn* c);
static err_t web_send_body(struct tcp_pcb* tpcb, struct web_send* ws) {
    sp_note();
    STAGE(9);
    while (ws->off < ws->len) {
        u16_t room = tcp_sndbuf(tpcb);
        if (room == 0) { tcp_output(tpcb); return ERR_OK; }   // full: wait for tcp_sent
        int chunk = ws->len - ws->off;
        if (chunk > (int)room) chunk = room;
        u8_t flags = ws->copy ? TCP_WRITE_FLAG_COPY : 0;
        if (ws->off + chunk < ws->len) flags |= TCP_WRITE_FLAG_MORE;
        err_t e = tcp_write(tpcb, ws->body + ws->off, (u16_t)chunk, flags);
        if (e == ERR_MEM) { tcp_output(tpcb); return ERR_OK; } // pbufs exhausted: retry on tcp_sent
        if (e != ERR_OK) { web_finish(tpcb, (struct web_conn*)ws->conn); return ERR_OK; }
        ws->off += chunk;
    }
    tcp_output(tpcb);
    // all bytes queued: wait for the ACKs, web_sent() aborts once they are all in
    if (ws->acked >= ws->len) return web_abort_done(tpcb, (struct web_conn*)ws->conn);
    return ERR_OK;
}

// 2026-10-28: a graceful tcp_close() returned ERR_OK and the board still halted right after, so
// the FIN/TIME_WAIT path is suspect. Keep the connection open until the peer has acknowledged
// every body byte, then abort: the response is already delivered, and no FIN/close state is left.
static err_t web_abort_done(struct tcp_pcb* tpcb, struct web_conn* c) {
    STAGE(16);
    tcp_arg(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_err(tpcb, NULL);
    tcp_poll(tpcb, NULL, 0);
    tcp_abort(tpcb);
    STAGE(17);          // tcp_abort returned
    conn_free(c);
    STAGE(18);          // conn_free returned
    return ERR_ABRT;
}

static err_t web_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    STAGE(12);
    struct web_conn* c = (struct web_conn*)arg;
    if (c && c->ws) {
        c->ws->acked += (int)len;
        if (c->ws->off < c->ws->len) return web_send_body(tpcb, c->ws);
        if (c->ws->acked >= c->ws->len) return web_abort_done(tpcb, c);
    }
    return ERR_OK;
}

static void web_err(void* arg, err_t err) {
    (void)err;
    // lwIP has already freed the pcb; only our record and cursor remain.
    conn_free((struct web_conn*)arg);
    if (WEB_LOAD(&g_sends) == 0) web_apply_edits();   // a pending edit must not wait for a request
}

// Small single-write response (fits one sndbuf by construction). Returns false if it did not fit or
// a write failed - a free sndbuf does not guarantee the pbuf allocation succeeds.
static bool web_small(struct tcp_pcb* tpcb, const char* a, const char* b, const char* c) {
    size_t n = strlen(a) + (b ? strlen(b) : 0) + (c ? strlen(c) : 0);
    if (tcp_sndbuf(tpcb) < (u16_t)n) return false;
    if (tcp_write(tpcb, a, (u16_t)strlen(a), TCP_WRITE_FLAG_COPY) != ERR_OK) return false;
    if (b && tcp_write(tpcb, b, (u16_t)strlen(b), TCP_WRITE_FLAG_COPY) != ERR_OK) return false;
    if (c && tcp_write(tpcb, c, (u16_t)strlen(c), TCP_WRITE_FLAG_COPY) != ERR_OK) return false;
    tcp_output(tpcb);
    return true;
}

static void web_resolve_now(void);

static err_t web_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    (void)err;
    sp_note();
    STAGE(2);
    struct web_conn* c = (struct web_conn*)arg;
    if (p == NULL) {                       // peer closed: free any in-flight cursor, then close
        web_finish(tpcb, c);
        return ERR_OK;
    }
    // A further segment while a response is still streaming (POST body, extra headers) must not
    // re-enter: it would restart the response and leak the cursor. Just drain it.
    if (c && c->ws) { tcp_recved(tpcb, p->tot_len); pbuf_free(p); return ERR_OK; }

    // Accumulate until the request line is complete. Copying only the first pbuf truncated the
    // path whenever the request was split, which lost the query string (and with it the capture).
    if (!c) { tcp_recved(tpcb, p->tot_len); pbuf_free(p); web_finish(tpcb, NULL); return ERR_OK; }
    {
        uint16_t space = (uint16_t)(sizeof(c->req) - 1 - c->req_len);
        uint16_t want = p->tot_len < space ? p->tot_len : space;
        if (want) c->req_len += pbuf_copy_partial(p, c->req + c->req_len, want, 0);
        c->req[c->req_len] = 0;
    }
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    if (!memchr(c->req, '\n', c->req_len)) {
        // Incomplete line: wait for the next segment. Oversized junk is dropped so a peer cannot
        // pin the buffer forever.
        if (c->req_len >= (uint16_t)(sizeof(c->req) - 1)) { c->req_len = 0; c->req[0] = 0; }
        return ERR_OK;
    }
    char* req = c->req;
    __atomic_add_fetch(&g_reqs, 1u, __ATOMIC_RELAXED);
    STAGE(3);

    if (!web_portal) {
        // --- WebUI mode: serve the render() status page to any request ---
        if (web_render) {
            web_render(g_body, sizeof(g_body));
            size_t bl = strlen(g_body);
            char hdr[160]; int hl = http_hdr(hdr, bl, false);
            if (tcp_sndbuf(tpcb) >= (u16_t)(hl + (int)bl) &&
                tcp_write(tpcb, hdr, (u16_t)hl, TCP_WRITE_FLAG_COPY) == ERR_OK &&
                tcp_write(tpcb, g_body, (u16_t)bl, TCP_WRITE_FLAG_COPY) == ERR_OK) {
                tcp_output(tpcb);
            }
        }
        web_finish(tpcb, c);
        return ERR_OK;
    }

    // --- captive-portal mode: parse the path from "GET <path> HTTP/1.1" ---
    char* path = NULL;
    char* sp = strchr(req, ' ');
    if (sp) { path = sp + 1; char* sp2 = strchr(path, ' '); if (sp2) *sp2 = 0; }
    if (!path || !*path) { web_finish(tpcb, c); return ERR_OK; }

    const uint32_t peer = ip_addr_get_ip4_u32(&tpcb->remote_ip);
    bool authed = ip_authed(peer);

    // credential capture: a query string with '=' is a form submission -> park it for loop(),
    // authorize the client, and advance the portal rotation (if enabled).
    char* q = strchr(path, '?');
    if (q && strchr(q, '=')) {
        STAGE(4);
        // EXPERIMENT 2026-10-28: the query branch is a no-op. Does the device still halt on a URL
        // with ? and =? If yes the branch contents are irrelevant; if no, bisect the branch.
        creds_push(q + 1);
        // STEP C: libc-free predicate. The stock one calls strchr/strlen/memchr, which this build
        // rewrites with -Wl,--wrap; a hand-rolled scan has no external calls at all.
        if (cred_query(q + 1)) {
            ip_mark_authed(peer);
            authed = true;
            if (web_rotate) web_rotate();
        }
    }

    if (strncmp(path, "/cp.json", 8) == 0) {
        STAGE(5);
        char* body = g_body;
        strcpy(body, "{\"captive\":");
        strcpy(body + strlen(body), authed ? "false" : "true");
        strcpy(body + strlen(body), ",\"user-portal-url\":\"");
        strcpy(body + strlen(body), g_root);
        strcpy(body + strlen(body), "\"}");
        if (!web_small(tpcb, "HTTP/1.1 200 OK\r\nContent-Type: application/captive+json\r\n"
                             "Connection: close\r\n\r\n", body, NULL)) {
            web_finish(tpcb, c); return ERR_OK;
        }
        web_finish(tpcb, c);
        return ERR_OK;
    }
    if (petrel_is_probe_path(path)) {
        STAGE(6);
        if (authed || web_probe_always204) {
            // Windows NCSI/connecttest validate a BODY, not just a status: a bare 204 leaves the
            // warning up there. Everything else takes the empty 204.
            const char* body = NULL;
            const char* ctype = "text/plain";
            if (petrel_probe_wants_body(path)) {
                body = strstr(path, "ncsi") ? "Microsoft NCSI" : "Microsoft Connect Test";
            }
            if (body) {
                if (!web_small(tpcb, "HTTP/1.1 200 OK\r\nContent-Type: ", ctype,
                               "\r\nConnection: close\r\n\r\n") ||
                    !web_small(tpcb, body, NULL, NULL)) { web_finish(tpcb, c); return ERR_OK; }
            } else if (!web_small(tpcb, NO_CONTENT_RESP, NULL, NULL)) {
                web_finish(tpcb, c); return ERR_OK;
            }
        } else if (!web_small(tpcb, REDIRECT_HEAD, g_root, REDIRECT_TAIL)) {
            web_finish(tpcb, c); return ERR_OK;
        }
        web_finish(tpcb, c);
        return ERR_OK;
    }

    // --- serve the SELECTED portal page (streamed: body may exceed one sndbuf) ---
    STAGE(7);
    if (WEB_LOAD(&g_sends) == 0) { web_apply_edits(); web_resolve_now(); }
    STAGE(8);   // never mid-stream
    const char* body = g_portal_body ? g_portal_body : PORTAL_BODY;
    int len          = g_portal_body ? g_portal_len  : (int)(sizeof(PORTAL_BODY) - 1);
    bool gzip        = g_portal_body ? g_portal_gzip : false;
    bool copy        = g_portal_body ? g_portal_copy : false;

    char hdr[180]; int hl = http_hdr(hdr, (size_t)len, gzip);
    if (tcp_sndbuf(tpcb) < (u16_t)hl) { web_finish(tpcb, c); return ERR_OK; }  // header must fit
    if (tcp_write(tpcb, hdr, (u16_t)hl, TCP_WRITE_FLAG_COPY) != ERR_OK) {      // header on stack
        web_finish(tpcb, c); return ERR_OK;
    }

    struct web_send* ws = (struct web_send*)mem_malloc(sizeof(struct web_send));
    if (!ws) { tcp_output(tpcb); web_finish(tpcb, c); return ERR_OK; }         // header only
    ws->body = body; ws->len = len; ws->off = 0; ws->copy = copy ? 1 : 0; ws->conn = c;
    ws->acked = -hl;   // 2026-10-28: tcp_sent() also acks the header bytes queued above
    c->ws = ws;
    WEB_ADD(&g_sends, 1u);
    tcp_sent(tpcb, web_sent);
    return web_send_body(tpcb, ws);
}

static err_t web_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
    (void)arg; (void)err;
    if (newpcb == NULL) return ERR_VAL;
    STAGE(1);
    struct web_conn* c = conn_add(newpcb);
    if (!c) { tcp_abort(newpcb); return ERR_ABRT; }   // no slot: refuse rather than track nothing
    tcp_arg(newpcb, c);
    tcp_err(newpcb, web_err);                        // installed now, not only once streaming
    tcp_recv(newpcb, web_recv);
    tcp_poll(newpcb, web_poll, 8 /* ~4s */);
    return ERR_OK;
}

static bool web_listen_start() {
    if (web_listen) return true;
    struct tcp_pcb* pcb = tcp_new();
    if (!pcb) return false;
    if (tcp_bind(pcb, IP_ADDR_ANY, 80) != ERR_OK) { tcp_close(pcb); return false; }
    // NOTE: on failure tcp_listen() leaves pcb allocated (it only frees it on success), so the
    // tcp_close() below is correct and NOT a double free.
    web_listen = tcp_listen(pcb);
    if (!web_listen) { tcp_close(pcb); return false; }
    tcp_accept(web_listen, web_accept);
    return true;
}

// The raw API is not thread-safe and this port runs with LWIP_TCPIP_CORE_LOCKING=0, so every pcb
// list mutation is marshalled into the tcpip thread (blocking, so the callers keep sync semantics).
// The configuration globals are published BEFORE the callback runs; only tcpip callbacks read them.
struct web_lifecycle { bool start; bool ok; };

static void web_lifecycle_cb(void* ctx) {
    struct web_lifecycle* lc = (struct web_lifecycle*)ctx;
    if (lc->start) {
        web_abort_conns();          // a start while active must not inherit old cursors
        // Session state is reset HERE, after the abort: resetting it in the caller would let a
        // receive callback see g_sends == 0 while an old stream still holds a page pointer.
        g_creds_head = 0; g_creds_tail = 0; g_creds_drop = 0;
        g_authed_n = 0; g_authed_next = 0;
        web_resolve_now();          // page pointer published in the tcpip thread
        lc->ok = web_listen_start();
    } else {
        web_abort_conns();
        if (web_listen) { tcp_close(web_listen); web_listen = NULL; }
    }
    WEB_STORE(&web_cb_done, true);
}

// tcpip_callback_with_block(block=1) only waits until the message is POSTED, not until the callback
// has run, so stack arguments would expire. The arguments are therefore static (every caller is
// loop()) and a done flag gives the caller synchronous semantics - a callback that arrives late is
// still safe because its storage outlives it.
// Waits until the callback has actually RUN. Every caller is loop(), so operations never overlap -
// that is what makes the single done flag and the static arguments safe. Both waits are unbounded:
// the tcpip thread always drains its mailbox and frees the message, and the AP lifecycle already
// depends on it. There is deliberately no direct-call fallback - running raw lwIP calls from loop()
// while tcpip is live is exactly what this exists to avoid.
static void web_in_tcpip(web_tcpip_cb fn, void* ctx) {
    WEB_STORE(&web_cb_done, false);
    while (tcpip_callback_with_block(fn, ctx, 1) != ERR_OK) delay(1);   // pool exhausted: retry
    while (!WEB_LOAD(&web_cb_done)) delay(1);   // acquire: the callback's writes are visible
}

static struct web_lifecycle web_lc;   // static: the callback may outlive this call

static bool web_lifecycle(bool start) {
    web_lc.start = start; web_lc.ok = false;
    web_in_tcpip(web_lifecycle_cb, &web_lc);
    return web_lc.ok;
}

bool web_lwip_start(void (*render)(char* buf, size_t cap)) {
    web_render = render; web_portal = false;
    return web_lifecycle(true);
}

static void web_set_resolver_cb(void* ctx) {
    web_resolve = *(web_resolve_fn*)ctx;
    WEB_STORE(&web_cb_done, true);
}

static web_resolve_fn web_resolver_arg;

void web_lwip_set_resolver(web_resolve_fn fn) {
    web_resolver_arg = fn;
    web_in_tcpip(web_set_resolver_cb, &web_resolver_arg);
}

// Re-resolve the page. Only called when no response is streaming, so the previous body pointer is
// no longer referenced by anyone.
static void web_resolve_now(void) {
    const char* b = NULL; int l = 0; bool g = false, c = false;
    if (web_resolve) web_resolve(&b, &l, &g, &c);
    g_portal_body = (b && l > 0) ? b : NULL;
    g_portal_len  = l; g_portal_gzip = g; g_portal_copy = c;
}

bool web_lwip_start_portal(void) {
    web_render = NULL; web_portal = true;
    return web_lifecycle(true);   // aborts stale conns, resets state and resolves in tcpip
}

struct web_url_args { const char* root; };

static void web_set_urls_cb(void* ctx) {
    const char* root = ((struct web_url_args*)ctx)->root;
    if (root && root[0]) {
        strncpy(g_root, root, sizeof(g_root) - 1); g_root[sizeof(g_root) - 1] = 0;
    }
    WEB_STORE(&web_cb_done, true);
}

void web_lwip_set_urls(const char* root, const char* cpjson) {
    (void)cpjson;   // the cp.json URL is derived from root at request time
    static struct web_url_args a;
    a.root = root;
    web_in_tcpip(web_set_urls_cb, &a);
}

static void web_set_rotate_cb(void* ctx) {
    web_rotate = *(void (**)(void))ctx;
    WEB_STORE(&web_cb_done, true);
}

static void (*web_rotate_arg)(void);

void web_lwip_set_rotate(void (*fn)(void)) {
    web_rotate_arg = fn;
    web_in_tcpip(web_set_rotate_cb, &web_rotate_arg);
}

bool web_lwip_poll_creds(char* buf, int cap) {
    unsigned h = WEB_LOAD(&g_creds_head);
    if (h == WEB_LOAD(&g_creds_tail)) return false;   // acquire: slot visible after the index
    int n = (int)strlen(g_creds[h]);
    if (n > cap - 1) n = cap - 1;
    memcpy(buf, g_creds[h], n); buf[n] = 0;
    WEB_STORE(&g_creds_head, (h + 1) % CRED_SLOTS);   // release: slot drained
    return true;
}

unsigned web_lwip_creds_dropped(void) { return WEB_LOAD(&g_creds_drop); }

// customPortal edits run in the tcpip thread and only while no response is streaming: a stream keeps
// the pointer and the ORIGINAL length, so rewriting the bytes under it would mix old and new content.
// Exactly one edit can be outstanding (every caller blocks), so a single pending slot is enough.
// If a stream refuses to finish, the caller's bounded wait aborts the connections, which guarantees
// progress instead of letting a busy client starve loop().
static void (*g_edit_fn)(const void*);
static const void* g_edit_arg;
static bool g_edit_pending;

static void web_apply_edits(void) {   // tcpip thread, only when idle
    static bool running = false;
    if (!WEB_LOAD(&g_edit_pending) || running || WEB_LOAD(&g_sends) != 0) return;
    running = true;
    void (*fn)(const void*) = g_edit_fn;
    const void* arg = g_edit_arg;
    fn(arg);                          // execute FIRST: the waiter's argument must still be alive
    running = false;
    WEB_STORE(&g_edit_pending, false);   // release: the caller may now read the result and drop `arg`
}

static void web_portal_edit_cb(void* ctx) {
    (void)ctx;
    web_apply_edits();
    WEB_STORE(&web_cb_done, true);
}

static void web_abort_cb(void* ctx) { (void)ctx; web_abort_conns(); WEB_STORE(&web_cb_done, true); }

// Read-only run in tcpip: no idle requirement, so a status read never disturbs a download.
static void web_in_tcpip_cb(void* ctx) {
    const struct web_fn_arg* e = (const struct web_fn_arg*)ctx;
    e->fn(e->arg);
    WEB_STORE(&web_cb_done, true);
}

void web_lwip_in_tcpip(void (*fn)(const void*), const void* arg) {
    static struct web_fn_arg e;
    e.fn = fn; e.arg = arg;
    web_in_tcpip(web_in_tcpip_cb, &e);
}

void web_lwip_portal_edit(void (*fn)(const void*), const void* arg) {
    g_edit_fn = fn; g_edit_arg = arg;
    WEB_STORE(&g_edit_pending, true);   // release: the slot is visible before it is published
    web_in_tcpip(web_portal_edit_cb, NULL);
    // Wait for the edit to actually run: the argument may be a temporary and the reply must be
    // truthful. The bound below covers the CLIENT side only; the marshal above additionally waits
    // for the tcpip thread to service the callback, which the whole AP lifecycle depends on anyway.
    uint32_t t0 = millis();
    while (WEB_LOAD(&g_edit_pending) && (uint32_t)(millis() - t0) < 2000) delay(1);
    if (WEB_LOAD(&g_edit_pending)) {
        web_in_tcpip(web_abort_cb, NULL);   // drop the streams, which lets the edit land
        t0 = millis();
        while (WEB_LOAD(&g_edit_pending) && (uint32_t)(millis() - t0) < 2000) delay(1);
    }
}


void web_lwip_stop() {
    web_lifecycle(false);
    web_portal = false;
    g_creds_head = 0; g_creds_tail = 0;
    g_portal_body = NULL; g_portal_len = 0;
    g_authed_n = 0; g_authed_next = 0;
}
