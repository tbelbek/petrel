// Host-side self-test for RTL8720dn-firmware/dhcp_build.h (no lwip/device needed).
// Build: cc -I ../RTL8720dn-firmware test_dhcp_build.c -o /tmp/t && /tmp/t
// Verifies: OFFER/ACK type, yiaddr on the 192.168.4.0/24 captive subnet, and that the
// RFC 8910 option 114 (Captive-Portal URI) is present and points at /cp.json.
#include <stdio.h>
#include <string.h>
#include "dhcp_build.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
                              else { printf("ok  : %s\n", msg); } } while (0)

static size_t build_req(uint8_t *req, uint8_t msg_type) {
    memset(req, 0, 300);
    req[0] = 1;                 // op = BOOTREQUEST
    req[1] = 1;                 // htype = ethernet
    req[2] = 6;                 // hlen
    req[4] = 0xAA; req[5] = 0xBB; req[6] = 0xCC; req[7] = 0xDD;  // xid
    req[28] = 0xEA; req[33] = 0x11;  // chaddr (chaddr[5]=0x11 -> yiaddr .117 if %101)
    memcpy(req + DHCP_FIXED_LEN, DHCP_MAGIC, 4);
    uint8_t *o = req + DHCP_FIXED_LEN + 4;
    *o++ = 53; *o++ = 1; *o++ = msg_type;   // DHCP message type
    *o++ = 255;                              // END
    return (size_t)(o - req);
}

static const char *TEST_URI = "http://freewifi.com/cp.json";

static void expect_reply(uint8_t msg_type, uint8_t want_reply_type, const char *label) {
    uint8_t req[300], out[600];
    size_t rl = build_req(req, msg_type);
    size_t n = dhcp_build_reply(out, sizeof(out), req, rl, TEST_URI);
    printf("\n-- %s --\n", label);
    CHECK(n >= DHCP_MIN_REPLY, "reply produced and >= DHCP_MIN_REPLY");
    CHECK(out[0] == 2, "op == BOOTREPLY");
    CHECK(memmem(out + DHCP_FIXED_LEN, 4, DHCP_MAGIC, 4) != NULL, "magic cookie intact");

    uint8_t tlen = 0;
    const uint8_t *t = dhcp_find_opt(out, n, 53, &tlen);
    CHECK(t && tlen == 1 && t[0] == want_reply_type, "message type = OFFER(2)/ACK(5) as expected");

    CHECK(out[16] == 192 && out[17] == 168 && out[18] == 4, "yiaddr subnet = 192.168.4.0/24");
    CHECK(out[19] >= 100 && out[19] <= 200, "yiaddr host in 100..200");

    uint8_t ul = 0;
    const uint8_t *u = dhcp_find_opt(out, n, 114, &ul);
    CHECK(u != NULL, "option 114 present");
    if (u) {
        char uri[64] = {0};
        memcpy(uri, u, ul < 63 ? ul : 63);
        printf("      option 114 = \"%s\" (len %u)\n", uri, ul);
        CHECK(strcmp(uri, TEST_URI) == 0, "option 114 = the URL passed in");
    }
    // END marker must be the last option
    CHECK(out[n - 1] == 255 || (n == DHCP_MIN_REPLY && out[n - 1] == 0), "option list terminated (END/pad)");
}

int main(void) {
    expect_reply(1, 2, "DISCOVER -> OFFER");
    expect_reply(3, 5, "REQUEST  -> ACK");

    // A bare packet (no magic) must be ignored, not answered.
    uint8_t junk[300] = {0};
    junk[0] = 1;
    CHECK(dhcp_build_reply(junk, sizeof(junk), junk, sizeof(junk), TEST_URI) == 0, "no magic cookie -> ignored");

    printf("\n%s (%d failure%s)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
