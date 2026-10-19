/* wids_test.c — standalone self-test for the passive WIDS detectors.
 * Build+run:  cc -I. -Wall -Wextra -o /tmp/wt common/wids_test.c && /tmp/wt
 * Replays synthetic frames (NO RF): proves deauth-flood fires on rate (not single frames),
 * evil-twin fires on RSN downgrade, a legit multi-BSSID ESS does NOT false-positive, and the
 * beacon parser extracts the right security class.
 */
#include "wids.h"
#include <assert.h>
#include <stdio.h>

/* build a minimal beacon: bssid, ssid, akm (2=PSK/WPA2, 8=SAE/WPA3, 0xFF=open/no-RSN) */
static unsigned mk_beacon(uint8_t* f, const uint8_t* bssid, const char* ssid, uint8_t akm) {
    unsigned n = 0, i;
    uint8_t sl = (uint8_t)strlen(ssid);
    f[n++] = 0x80;              /* fc: mgmt beacon (subtype 8) */
    f[n++] = 0x00;              /* flags */
    f[n++] = 0; f[n++] = 0;     /* duration */
    for (i = 0; i < 6; i++) f[n++] = 0xFF;          /* addr1 dst bcast */
    for (i = 0; i < 6; i++) f[n++] = bssid[i];      /* addr2 src */
    for (i = 0; i < 6; i++) f[n++] = bssid[i];      /* addr3 bssid */
    f[n++] = 0; f[n++] = 0;     /* seq */
    for (i = 0; i < 12; i++) f[n++] = 0;            /* timestamp8 + interval2 + caps2 */
    f[n++] = 0; f[n++] = sl;    /* SSID IE */
    for (i = 0; i < sl; i++) f[n++] = (uint8_t)ssid[i];
    if (akm != 0xFF) {          /* RSN IE */
        uint8_t rsn[22] = {48, 20, 1,0, 0,0x0F,0xAC,4, 1,0, 0,0x0F,0xAC,4, 1,0, 0,0x0F,0xAC,akm, 0,0};
        for (i = 0; i < 22; i++) f[n++] = rsn[i];
    }
    return n;
}

int main(void) {
    wids_state s;
    uint8_t srcA[6] = {0xAA,0,0,0,0,1}, srcB[6] = {0xBB,0,0,0,0,2};
    uint8_t ap1[6] = {0x7C,0x77,0x16,0x94,0x09,0x11};
    uint8_t ap2[6] = {0x8C,0x90,0x2D,0xA7,0x1C,0xA9};

    /* 1. deauth-flood: 25 deauth from srcA within one window -> exactly one alert (debounced) */
    {
        int alerts = 0, i;
        wids_init(&s);
        for (i = 0; i < 25; i++) alerts += (wids_feed_deauth(&s, srcA, 1000) == WIDS_DEAUTH_FLOOD);
        assert(alerts == 1);
    }
    /* 1b. roaming: a few deauth from srcB -> NO alert (rate-gated, not single-frame) */
    {
        int alerts = 0, i;
        wids_init(&s);
        for (i = 0; i < 5; i++) alerts += (wids_feed_deauth(&s, srcB, 1000) != WIDS_NONE);
        assert(alerts == 0);
    }
    /* 1c. window reset: 25 now, then 25 after the window + debounce -> two alerts */
    {
        int a1 = 0, a2 = 0, i;
        wids_init(&s);
        for (i = 0; i < 25; i++) a1 += (wids_feed_deauth(&s, srcA, 1000) == WIDS_DEAUTH_FLOOD);
        for (i = 0; i < 25; i++) a2 += (wids_feed_deauth(&s, srcA, 20000) == WIDS_DEAUTH_FLOOD);
        assert(a1 == 1 && a2 == 1);
    }

    /* 2. evil-twin: ap1 seen WPA3, then same SSID WPA2 -> downgrade alert; repeat -> debounced */
    {
        int a;
        wids_init(&s);
        a = wids_feed_beacon(&s, ap1, 0x1234, WIDS_SEC_WPA3, 1000); assert(a == WIDS_NONE); /* first */
        a = wids_feed_beacon(&s, ap1, 0x1234, WIDS_SEC_WPA3, 1100); assert(a == WIDS_NONE); /* same */
        a = wids_feed_beacon(&s, ap1, 0x1234, WIDS_SEC_WPA2, 1200); assert(a == WIDS_EVIL_TWIN);
        a = wids_feed_beacon(&s, ap1, 0x1234, WIDS_SEC_OPEN, 1300); assert(a == WIDS_NONE); /* debounce */
    }
    /* 3. FALSE-POSITIVE guard: two different BSSIDs, SAME ssid, both WPA3 (legit ESS) -> no alert */
    {
        int a1, a2;
        wids_init(&s);
        a1 = wids_feed_beacon(&s, ap1, 0x5678, WIDS_SEC_WPA3, 1000);
        a2 = wids_feed_beacon(&s, ap2, 0x5678, WIDS_SEC_WPA3, 1000);
        assert(a1 == WIDS_NONE && a2 == WIDS_NONE);
    }

    /* 4. parser: WPA3 / WPA2 / open frames classify correctly, same bssid+ssid_hash */
    {
        uint8_t f[128], bs[6]; uint16_t sh3, sh2; uint8_t sc;
        unsigned n;
        n = mk_beacon(f, ap1, "TestNet", 8);
        assert(wids_parse_beacon(f, n, bs, &sh3, &sc) == 1 && sc == WIDS_SEC_WPA3 && !memcmp(bs, ap1, 6));
        n = mk_beacon(f, ap1, "TestNet", 2);
        assert(wids_parse_beacon(f, n, bs, &sh2, &sc) == 1 && sc == WIDS_SEC_WPA2);
        assert(sh3 == sh2); /* same SSID -> same hash (so a downgrade is detected) */
        n = mk_beacon(f, ap1, "TestNet", 0xFF);
        assert(wids_parse_beacon(f, n, bs, &sh2, &sc) == 1 && sc == WIDS_SEC_OPEN);
        /* end-to-end: parsed WPA3 then parsed WPA2 for same AP -> evil-twin alert */
        wids_init(&s);
        n = mk_beacon(f, ap1, "TestNet", 8); wids_parse_beacon(f, n, bs, &sh3, &sc);
        assert(wids_feed_beacon(&s, bs, sh3, sc, 1000) == WIDS_NONE);
        n = mk_beacon(f, ap1, "TestNet", 2); wids_parse_beacon(f, n, bs, &sh2, &sc);
        assert(wids_feed_beacon(&s, bs, sh2, sc, 1200) == WIDS_EVIL_TWIN);
    }

    /* 5. beacon-flood: 25 NEW BSSIDs within one window -> WIDS_BEACON_FLOOD */
    {
        int a = WIDS_NONE, i;
        uint8_t b[6] = {0xDE, 0, 0, 0, 0, 0};
        wids_init(&s);
        for (i = 0; i < 25; i++) { b[5] = (uint8_t)i; a = wids_feed_beacon(&s, b, (uint16_t)(0x1000 + i), WIDS_SEC_WPA2, 500); }
        assert(a == WIDS_BEACON_FLOOD);
    }
    /* 5b. slow new-AP rate does NOT flood (window resets) */
    {
        int flood = 0, i;
        uint8_t b[6] = {0xDF, 0, 0, 0, 0, 0};
        wids_init(&s);
        for (i = 0; i < 25; i++) { b[5] = (uint8_t)i; if (wids_feed_beacon(&s, b, (uint16_t)(0x1000 + i), WIDS_SEC_WPA2, 500u + (uint32_t)i * 200u) == WIDS_BEACON_FLOOD) flood = 1; }
        assert(!flood); /* 200ms apart -> <25 per 3s window */
    }
    /* 6. KARMA: one BSSID advertising 6 distinct SSIDs -> WIDS_KARMA */
    {
        int a = WIDS_NONE, i;
        uint8_t b[6] = {0xCA, 0, 0, 0, 0, 1};
        wids_init(&s);
        for (i = 0; i < 6; i++) a = wids_feed_beacon(&s, b, (uint16_t)(0x2000 + i), WIDS_SEC_OPEN, 500);
        assert(a == WIDS_KARMA);
    }
    /* 6b. a stable AP (same SSID) never looks like KARMA */
    {
        int karma = 0, i;
        uint8_t b[6] = {0xCB, 0, 0, 0, 0, 1};
        wids_init(&s);
        for (i = 0; i < 20; i++) if (wids_feed_beacon(&s, b, 0x2222, WIDS_SEC_WPA2, 500) == WIDS_KARMA) karma = 1;
        assert(!karma);
    }

    printf("wids self-test: OK\n");
    return 0;
}
