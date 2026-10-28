#include "lwip_call.h"
#include <lwip/err.h>
// Declared locally instead of including <lwip/tcpip.h>: that header pulls sys.h, whose sys_now()
// collides with the core's C-linkage declaration.
extern "C" {
typedef void (*lwip_call_fn)(void* ctx);
err_t tcpip_callback_with_block(lwip_call_fn function, void* ctx, u8_t block);
unsigned long millis(void);
void delay(unsigned long ms);
}

static bool s_done;
struct lwip_call_req { void (*fn)(void*); void* ctx; };

static void lwip_call_cb(void* p) {
    struct lwip_call_req* r = (struct lwip_call_req*)p;
    r->fn(r->ctx);
    __atomic_store_n(&s_done, true, __ATOMIC_RELEASE);
}

void lwip_call(void (*fn)(void*), void* ctx) {
    static struct lwip_call_req req;   // static: the callback may outlive this call
    req.fn = fn; req.ctx = ctx;
    __atomic_store_n(&s_done, false, __ATOMIC_RELAXED);
    // tcpip_callback_with_block(block=1) only waits until the message is POSTED, so wait for the
    // callback itself. The pool can be exhausted; retry rather than run raw API calls from loop().
    while (tcpip_callback_with_block(lwip_call_cb, &req, 1) != ERR_OK) delay(1);
    while (!__atomic_load_n(&s_done, __ATOMIC_ACQUIRE)) delay(1);
}
