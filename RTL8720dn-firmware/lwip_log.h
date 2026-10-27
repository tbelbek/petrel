// Deferred log for the lwIP/tcpip thread.
//
// The DHCP and DNS servers run in the tcpip thread. A blocking UART write there stalls the whole
// stack (and Serial1 is shared with loop(), so writing from two threads corrupts lines). So the
// hot paths format into a small ring and loop() drains it to both UARTs.
//
// Single producer (tcpip thread) / single consumer (loop). Ring full -> drop newest and count it,
// so an overrun is visible instead of silent.
#ifndef LWIP_LOG_H
#define LWIP_LOG_H
#include <stdbool.h>

void lwip_log(const char* s);                 // producer: tcpip thread only
bool lwip_log_poll(char* out, int cap);       // consumer: loop() only
unsigned lwip_log_dropped(void);
#endif
