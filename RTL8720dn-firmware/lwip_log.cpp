#include "lwip_log.h"
#include <string.h>

// Acquire/release accessors (volatile alone is not synchronization on this weakly-ordered part).
#define LL_LOAD(p)     __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define LL_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define LL_SLOTS 4
#define LL_LEN   64

static char     ll_buf[LL_SLOTS][LL_LEN];
static unsigned ll_head = 0;   // consumer
static unsigned ll_tail = 0;   // producer
static unsigned ll_drop = 0;

void lwip_log(const char* s) {
    if (!s) return;
    unsigned t = LL_LOAD(&ll_tail);
    unsigned h = LL_LOAD(&ll_head);
    if ((t + 1) % LL_SLOTS == h) { __atomic_add_fetch(&ll_drop, 1u, __ATOMIC_RELAXED); return; }
    size_t n = strlen(s);
    if (n > LL_LEN - 1) n = LL_LEN - 1;
    memcpy(ll_buf[t], s, n);
    ll_buf[t][n] = 0;
    LL_STORE(&ll_tail, (t + 1) % LL_SLOTS);   // release
}

bool lwip_log_poll(char* out, int cap) {
    unsigned h = LL_LOAD(&ll_head);
    if (h == LL_LOAD(&ll_tail)) return false;   // acquire
    size_t n = strlen(ll_buf[h]);
    if (n > (size_t)(cap - 1)) n = (size_t)(cap - 1);
    memcpy(out, ll_buf[h], n);
    out[n] = 0;
    LL_STORE(&ll_head, (h + 1) % LL_SLOTS);   // release
    return true;
}

unsigned lwip_log_dropped(void) { return LL_LOAD(&ll_drop); }
