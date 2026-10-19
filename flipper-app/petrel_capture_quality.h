// petrel_capture_quality — rigorous WPA 4-way-handshake EAPOL capture validator.
//
// Pure logic, NO Flipper/Arduino deps, so it host-compiles for offline unit tests
// (common/petrel_capture_quality_test.c). It ingests 802.11 data frames, keeps only the EAPOL-Key
// frames that pass full structural validation (frame control, DS bits, QoS/HT header length, LLC/
// SNAP, EAPOL-Key descriptor + key-info sanity, non-degenerate nonce/MIC), de-duplicates, and then
// decides crackability from a SINGLE consistent exchange: an M1+M2 pair on the same (BSSID, STA)
// with equal replay counters, or (fallback) M2+M3 with replay+1 and a matching ANonce. This is far
// stronger than "some M1 and some M2 are present", which can pair frames from different handshakes.
//
// Validation follows the IEEE 802.11 EAPOL-Key 4-way-handshake structure (RSN/WPA), the same checks
// hostapd / wpa_supplicant / aircrack-style tools apply. Independent implementation.
#ifndef PETREL_CAPTURE_QUALITY_H
#define PETREL_CAPTURE_QUALITY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PCQ_MAX_RECORDS
#define PCQ_MAX_RECORDS 16
#endif

typedef enum {
    PcqAccepted = 0,     // stored as a valid EAPOL-Key record
    PcqDuplicate,        // identical to a record already held
    PcqNotEapol,         // not an 802.11 data frame carrying clear EAPOL-Key
    PcqWrongBssid,       // BSSID != the audit target
    PcqUnsupportedDs,    // ToDS==FromDS (not a station<->AP data frame)
    PcqTruncated,        // too short for its claimed headers/body
    PcqBadEapolLength,   // 802.1X length field inconsistent / too small
    PcqBadKeyDescriptor, // not RSN (2) or WPA (254)
    PcqBadKeyInfo,       // not a pairwise key-info we can use (version/flags)
    PcqBadNonce,         // nonce all-zero / all-0xFF where it must carry entropy
    PcqBadMic,           // MIC degenerate (or non-zero on M1 where none exists yet)
    PcqCapacity,         // record store full
} PcqIngest;

typedef enum { PcqPairNone = 0, PcqPairM1M2, PcqPairM2M3 } PcqPair;

typedef struct {
    uint8_t message;     // 1..4
    uint8_t desc;        // EAPOL-Key descriptor type (2 = RSN, 254 = WPA) - must match across a pair
    uint8_t kver;        // key-info key-descriptor version (1..3) - must match across a pair
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t replay[8];
    uint8_t nonce[32];
    uint8_t mic[16];
} PcqRecord;

typedef struct {
    uint8_t  target_bssid[6];
    bool     target_set;
    PcqRecord records[PCQ_MAX_RECORDS];
    uint8_t  count;
    uint16_t duplicates;
    uint16_t rejects[12];   // per-PcqIngest-category tally (why frames were dropped) = failure evidence
    uint8_t  msg_mask;   // bit i set if message i (1..4) seen
    PcqPair  pair;
} PetrelCaptureQuality;

// Reset the validator. Pass the audit target BSSID to reject off-target frames, or NULL to accept
// any BSSID (the first accepted frame's BSSID is NOT auto-locked — pairing is still per (BSSID,STA)).
void pcq_reset(PetrelCaptureQuality* q, const uint8_t target_bssid[6]);

// Ingest one raw 802.11 frame. Returns the classification; only PcqAccepted is stored.
PcqIngest pcq_ingest(PetrelCaptureQuality* q, const uint8_t* frame, size_t length);

// True once a crackable, exchange-consistent pair exists.
bool pcq_has_pair(const PetrelCaptureQuality* q);

// Human-readable one-liner, e.g. "M1 M2 OK" / "M1 M2 no valid pair" / "M1 only" / "incomplete".
void pcq_summary(const PetrelCaptureQuality* q, char* out, size_t cap);

// The dominant drop reason (failure evidence), e.g. "off-target", "truncated", "dup", or "" when
// nothing notable was rejected. Helps explain WHY a capture is not usable.
void pcq_reject_brief(const PetrelCaptureQuality* q, char* out, size_t cap);

// Full per-category tally as "acc=N dup=N not-eapol=N ..." (only non-zero categories). The complete
// ingestion histogram = reproducible failure evidence for the audit report, not just one dominant
// reason. snprintf-free (same contract as pcq_summary).
void pcq_histogram(const PetrelCaptureQuality* q, char* out, size_t cap);

#endif
