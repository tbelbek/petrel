// Stack-depth probe for the lwIP tcpip thread (2026-10-28).
// The tcpip task has ~4 KB and the SDK calls the stack-overflow hook from inside PendSV with
// interrupts masked, so an overflow there stops every task and keeps the WiFi MAC beaconing.
// xTaskGetHandle/uxTaskGetStackHighWaterMark do not link, but the stack pointer is free: SP starts
// at the top of the task stack and grows down, so the lowest SP ever seen is the deepest usage.
// g_sp_base is sampled from the same cheap tcpip callback every second, giving a baseline that
// does not include a DNS/HTTP frame; (base - min) is the deepest callback stack cost.
#ifndef SP_PROBE_H
#define SP_PROBE_H
#include <stdint.h>

static inline uint32_t sp_read(void) {
    uint32_t v;
    __asm volatile("mov %0, sp" : "=r"(v));
    return v;
}

extern volatile uint32_t g_sp_min;    // lowest SP seen anywhere in the tcpip thread
extern volatile uint32_t g_sp_base;   // SP inside the 1 Hz callback (no callback frames below it)

static inline void sp_note(void) {
    uint32_t v = sp_read();
    if (v < g_sp_min) g_sp_min = v;
}
#endif
