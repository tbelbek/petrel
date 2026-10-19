// Host self-test for petrel_capture_quality. Build: cc -O2 -Wall petrel_capture_quality.c
// petrel_capture_quality_test.c -o t && ./t
#include "petrel_capture_quality.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// key-info words (big-endian) for each message, pairwise + version 2
#define KI_M1 0x008Au
#define KI_M2 0x010Au
#define KI_M3 0x03CAu

// Build a non-QoS 802.11 data frame carrying one EAPOL-Key message. From-DS for M1/M3 (AP->STA),
// To-DS for M2 (STA->AP). nonce/mic patterns let us exercise the degenerate-value rejects.
static size_t build(uint8_t* f, int msg, const uint8_t* bssid, const uint8_t* sta,
                    const uint8_t replay[8], uint8_t nonce_fill, uint8_t mic_fill) {
    memset(f, 0, 160);
    f[0] = 0x08;                        // data frame, non-QoS
    int from_ds = (msg == 1 || msg == 3);
    f[1] = from_ds ? 0x02 : 0x01;
    if(from_ds) { memcpy(f + 4, sta, 6); memcpy(f + 10, bssid, 6); }   // addr1=STA, addr2=BSSID
    else        { memcpy(f + 4, bssid, 6); memcpy(f + 10, sta, 6); }   // addr1=BSSID, addr2=STA
    uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    memcpy(f + 24, llc, 8);
    uint8_t* e = f + 32;
    e[0] = 2; e[1] = 3;                 // 802.1X v2, EAPOL-Key
    e[2] = 0; e[3] = 95;                // body length = 95
    e[4] = 2;                           // RSN descriptor
    uint16_t ki = msg == 1 ? KI_M1 : msg == 2 ? KI_M2 : KI_M3;
    e[5] = (ki >> 8) & 0xFF; e[6] = ki & 0xFF;
    memcpy(e + 9, replay, 8);
    memset(e + 17, nonce_fill, 32);
    memset(e + 81, mic_fill, 16);
    return 135;
}

// QoS-data variant: header is 26 bytes (24 + 2-byte QoS control), so LLC/SNAP and the EAPOL body
// sit two bytes later. Exercises the validator's QoS offset path (Codex-flagged as untested).
static size_t build_qos(uint8_t* f, int msg, const uint8_t* bssid, const uint8_t* sta,
                        const uint8_t replay[8], uint8_t nonce_fill, uint8_t mic_fill) {
    memset(f, 0, 160);
    f[0] = 0x88;                        // data frame, QoS subtype (bit 0x80 in the subtype nibble)
    int from_ds = (msg == 1 || msg == 3);
    f[1] = from_ds ? 0x02 : 0x01;
    if(from_ds) { memcpy(f + 4, sta, 6); memcpy(f + 10, bssid, 6); }
    else        { memcpy(f + 4, bssid, 6); memcpy(f + 10, sta, 6); }
    uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    memcpy(f + 26, llc, 8);             // +2 vs non-QoS
    uint8_t* e = f + 34;
    e[0] = 2; e[1] = 3;
    e[2] = 0; e[3] = 95;
    e[4] = 2;
    uint16_t ki = msg == 1 ? KI_M1 : msg == 2 ? KI_M2 : KI_M3;
    e[5] = (ki >> 8) & 0xFF; e[6] = ki & 0xFF;
    memcpy(e + 9, replay, 8);
    memset(e + 17, nonce_fill, 32);
    memset(e + 81, mic_fill, 16);
    return 34 + 99;
}

int main(void) {
    uint8_t f[160];
    uint8_t g[160];
    PetrelCaptureQuality q;
    char out[48];
    uint8_t ap[6]  = {0x7C,0x77,0x16,0x94,0x09,0x12};
    uint8_t sta[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t ap2[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t r1[8] = {0,0,0,0,0,0,0,1};
    uint8_t r2[8] = {0,0,0,0,0,0,0,2};

    // 1) valid M1+M2, same AP+STA, equal replay -> OK
    pcq_reset(&q, NULL);
    assert(pcq_ingest(&q, f, build(f, 1, ap, sta, r1, 0xA1, 0x00)) == PcqAccepted);
    assert(pcq_ingest(&q, f, build(f, 2, ap, sta, r1, 0xB2, 0xC2)) == PcqAccepted);
    pcq_summary(&q, out, sizeof(out)); printf("valid M1+M2 : %s\n", out);
    assert(pcq_has_pair(&q) && strstr(out, "OK"));

    // 2) M1+M2 different replay -> no pair
    pcq_reset(&q, NULL);
    pcq_ingest(&q, f, build(f, 1, ap, sta, r1, 0xA1, 0x00));
    pcq_ingest(&q, f, build(f, 2, ap, sta, r2, 0xB2, 0xC2));
    pcq_summary(&q, out, sizeof(out)); printf("RC mismatch : %s\n", out);
    assert(!pcq_has_pair(&q) && strstr(out, "no valid pair"));

    // 3) M1+M2 different STA -> no pair
    pcq_reset(&q, NULL);
    pcq_ingest(&q, f, build(f, 1, ap, sta, r1, 0xA1, 0x00));
    pcq_ingest(&q, f, build(f, 2, ap, ap2, r1, 0xB2, 0xC2));
    assert(!pcq_has_pair(&q));
    printf("STA mismatch: ok (no pair)\n");

    // 4) valid M2+M3 with replay+1 -> OK
    pcq_reset(&q, NULL);
    pcq_ingest(&q, f, build(f, 2, ap, sta, r1, 0xB2, 0xC2));
    pcq_ingest(&q, f, build(f, 3, ap, sta, r2, 0xA1, 0xD3));   // r2 = r1+1
    pcq_summary(&q, out, sizeof(out)); printf("valid M2+M3 : %s\n", out);
    assert(pcq_has_pair(&q) && strstr(out, "OK"));

    // 5) duplicate M1 -> PcqDuplicate
    pcq_reset(&q, NULL);
    assert(pcq_ingest(&q, f, build(f, 1, ap, sta, r1, 0xA1, 0x00)) == PcqAccepted);
    assert(pcq_ingest(&q, f, build(f, 1, ap, sta, r1, 0xA1, 0x00)) == PcqDuplicate);
    assert(q.count == 1 && q.duplicates == 1);
    printf("duplicate   : ok\n");

    // 6) wrong BSSID when a target is set + the failure reason surfaces
    pcq_reset(&q, ap);
    assert(pcq_ingest(&q, f, build(f, 1, ap2, sta, r1, 0xA1, 0x00)) == PcqWrongBssid);
    pcq_ingest(&q, f, build(f, 2, ap2, sta, r1, 0xB2, 0xC2));
    char rb[24]; pcq_reject_brief(&q, rb, sizeof(rb));
    printf("wrong bssid : ok (reject=%s)\n", rb);
    assert(strcmp(rb, "off-target") == 0);

    // 7) truncated
    pcq_reset(&q, NULL);
    assert(pcq_ingest(&q, f, 20) == PcqTruncated);
    printf("truncated   : ok\n");

    // 8) degenerate nonce (all zero on M2)
    pcq_reset(&q, NULL);
    assert(pcq_ingest(&q, f, build(f, 2, ap, sta, r1, 0x00, 0xC2)) == PcqBadNonce);
    printf("bad nonce   : ok\n");

    // 9) not EAPOL (break the LLC/SNAP)
    pcq_reset(&q, NULL);
    size_t n = build(f, 1, ap, sta, r1, 0xA1, 0x00); f[30] = 0x00;  // corrupt ethertype
    assert(pcq_ingest(&q, f, n) == PcqNotEapol);
    printf("not eapol   : ok\n");

    // 10) M1 with a non-zero MIC -> bad (M1 has no MIC yet)
    pcq_reset(&q, NULL);
    assert(pcq_ingest(&q, f, build(f, 1, ap, sta, r1, 0xA1, 0x55)) == PcqBadMic);
    printf("bad m1 mic  : ok\n");

    // 11) QoS-data M1+M2 -> OK (QoS header offset path)
    pcq_reset(&q, NULL);
    assert(pcq_ingest(&q, f, build_qos(f, 1, ap, sta, r1, 0xA1, 0x00)) == PcqAccepted);
    assert(pcq_ingest(&q, f, build_qos(f, 2, ap, sta, r1, 0xB2, 0xC2)) == PcqAccepted);
    assert(pcq_has_pair(&q));
    printf("qos M1+M2   : ok\n");

    // 12) direction mismatch: M1 key-info but sent ToDS (STA->AP) -> rejected
    pcq_reset(&q, NULL);
    { size_t n = build(f, 1, ap, sta, r1, 0xA1, 0x00); f[1] = 0x01; // force ToDS
      assert(pcq_ingest(&q, f, n) == PcqBadKeyInfo); }
    printf("dir mismatch: ok\n");

    // 13) key-data-length inconsistent with the 802.1X body length -> bad-eapol-len
    pcq_reset(&q, NULL);
    { size_t n = build(f, 1, ap, sta, r1, 0xA1, 0x00); f[32 + 97] = 0x00; f[32 + 98] = 0x10; // kdl=16, body=95
      assert(pcq_ingest(&q, f, n) == PcqBadEapolLength); }
    printf("kdl vs body : ok\n");

    // 14) bad 802.1X protocol version -> not eapol
    pcq_reset(&q, NULL);
    { size_t n = build(f, 1, ap, sta, r1, 0xA1, 0x00); f[32 + 0] = 0x00; // version 0
      assert(pcq_ingest(&q, f, n) == PcqNotEapol); }
    printf("eapol ver   : ok\n");

    // 15) M1 and M2 with mismatched key-descriptor version -> no crackable pair
    pcq_reset(&q, NULL);
    pcq_ingest(&q, f, build(f, 1, ap, sta, r1, 0xA1, 0x00));                 // kver 2
    { size_t n = build(f, 2, ap, sta, r1, 0xB2, 0xC2);
      f[32 + 6] = (uint8_t)((KI_M2 & 0xF8) | 1);                            // kver 1
      assert(pcq_ingest(&q, f, n) == PcqAccepted); }
    assert(!pcq_has_pair(&q));
    printf("kver pair   : ok (no pair)\n");

    // 16) M2+M3 fallback: a preceding M1 exists but for a DIFFERENT BSSID (same STA). The M1 search
    // must match BSSID too, so that stale M1 is ignored and the M2+M3 pair still forms.
    pcq_reset(&q, NULL);
    pcq_ingest(&q, g, build(g, 1, ap2, sta, r1, 0x5A, 0x00));                // M1 on ap2
    pcq_ingest(&q, f, build(f, 2, ap, sta, r1, 0xB2, 0xC2));                 // M2 on ap
    pcq_ingest(&q, f, build(f, 3, ap, sta, r2, 0x9D, 0xD3));                 // M3 on ap, r2=r1+1
    assert(pcq_has_pair(&q));
    printf("m2m3 bssid  : ok (pair)\n");

    // 17) histogram surfaces the per-category counts (not just one dominant reason)
    pcq_reset(&q, NULL);
    pcq_ingest(&q, f, 20);                                                    // truncated
    { size_t n = build(f, 1, ap, sta, r1, 0xA1, 0x00); f[30] = 0x00;          // not-eapol
      pcq_ingest(&q, f, n); }
    { char h[80]; pcq_histogram(&q, h, sizeof(h));
      printf("histogram   : %s\n", h);
      assert(strstr(h, "trunc") && strstr(h, "not-eapol")); }

    // 18) capacity: 17 distinct M1s (16-slot store) -> the 17th reports PcqCapacity
    pcq_reset(&q, NULL);
    { PcqIngest last = PcqAccepted;
      for(int i = 0; i < 17; i++) {
          uint8_t rr[8] = {0,0,0,0,0,0,0,(uint8_t)(i + 1)};
          last = pcq_ingest(&q, f, build(f, 1, ap, sta, rr, (uint8_t)(0x40 + i), 0x00));
      }
      assert(last == PcqCapacity && q.count == 16); }
    printf("capacity    : ok\n");

    printf("ALL PCQ TESTS PASSED\n");
    return 0;
}
