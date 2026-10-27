#include "lwip_log.h"
#include <string.h>

#define LL_SLOTS 4
#define LL_LEN   64

static char     ll_buf[LL_SLOTS][LL_LEN];
static volatile unsigned ll_head = 0;   // consumer
static volatile unsigned ll_tail = 0;   // producer
static volatile unsigned ll_drop = 0;

void lwip_log(const char* s) {
    if (!s) return;
    unsigned t = ll_tail;
    if ((t + 1) % LL_SLOTS == ll_head) { ll_drop++; return; }   // full: drop newest
    size_t n = strlen(s);
    if (n > LL_LEN - 1) n = LL_LEN - 1;
    memcpy(ll_buf[t], s, n);
    ll_buf[t][n] = 0;
    ll_tail = (t + 1) % LL_SLOTS;
}

bool lwip_log_poll(char* out, int cap) {
    unsigned h = ll_head;
    if (h == ll_tail) return false;
    size_t n = strlen(ll_buf[h]);
    if (n > (size_t)(cap - 1)) n = (size_t)(cap - 1);
    memcpy(out, ll_buf[h], n);
    out[n] = 0;
    ll_head = (h + 1) % LL_SLOTS;
    return true;
}

unsigned lwip_log_dropped(void) { return ll_drop; }
