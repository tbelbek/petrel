// Run a function in the lwIP tcpip thread and wait for it to finish.
//
// This port builds with LWIP_TCPIP_CORE_LOCKING=0, so the raw API (udp_new/udp_bind/udp_remove/
// tcp_new/...) must not be called from loop() while the tcpip thread is live. Every caller is
// loop(), so calls never overlap; the completion flag is an atomic acquire/release pair.
#ifndef LWIP_CALL_H
#define LWIP_CALL_H
#include <stdbool.h>

// Blocks until fn has run in the tcpip thread. Must NOT be called from the tcpip thread itself.
void lwip_call(void (*fn)(void*), void* ctx);
#endif
