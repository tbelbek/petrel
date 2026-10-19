#include "petrel_capture_quality.h"
#include <string.h>

// 802.11 frame control / EAPOL-Key key-info bit helpers.
#define PCQ_FTYPE_DATA 0x02u
#define PCQ_KI_PAIRWISE 0x0008u
#define PCQ_KI_INSTALL  0x0040u
#define PCQ_KI_ACK      0x0080u
#define PCQ_KI_MIC      0x0100u
#define PCQ_KI_SECURE   0x0200u
#define PCQ_KI_ERROR    0x0400u
#define PCQ_KI_REQUEST  0x0800u
#define PCQ_KI_SMK      0x2000u

static bool bytes_all(const uint8_t* d, size_t n, uint8_t v) {
    for(size_t i = 0; i < n; i++)
        if(d[i] != v) return false;
    return true;
}
// A nonce / MIC that is all 0x00 or all 0xFF carries no entropy -> a degenerate (useless) value.
static bool degenerate(const uint8_t* d, size_t n) {
    return bytes_all(d, n, 0x00) || bytes_all(d, n, 0xFF);
}
static bool mac_eq(const uint8_t* a, const uint8_t* b) {
    for(int i = 0; i < 6; i++)
        if(a[i] != b[i]) return false;
    return true;
}
static bool replay_eq(const uint8_t a[8], const uint8_t b[8]) {
    for(int i = 0; i < 8; i++)
        if(a[i] != b[i]) return false;
    return true;
}
// 64-bit big-endian: is `later` exactly `earlier` + 1 ?
static bool replay_next(const uint8_t earlier[8], const uint8_t later[8]) {
    uint8_t inc[8];
    memcpy(inc, earlier, 8);
    for(int i = 7; i >= 0; i--) {
        if(++inc[i] != 0) break; // no carry out of this byte
    }
    return replay_eq(inc, later);
}

static int classify(uint16_t ki) {
    bool ack = ki & PCQ_KI_ACK, mic = ki & PCQ_KI_MIC, sec = ki & PCQ_KI_SECURE, ins = ki & PCQ_KI_INSTALL;
    if(ack && !mic && !sec && !ins) return 1;
    if(!ack && mic && !sec && !ins) return 2;
    if(ack && mic && sec && ins) return 3;
    if(!ack && mic && sec && !ins) return 4;
    return 0;
}

static PcqIngest parse(const uint8_t* f, size_t len, PcqRecord* rec) {
    if(!f || len < 24) return PcqTruncated;
    if((f[0] & 0x03u) != 0) return PcqNotEapol;              // protocol version must be 0
    if(((f[0] >> 2) & 0x03u) != PCQ_FTYPE_DATA) return PcqNotEapol;
    if(f[1] & 0x40u) return PcqBadKeyInfo;                   // Protected frame -> not clear EAPOL
    bool to_ds = f[1] & 0x01u, from_ds = f[1] & 0x02u;
    if(to_ds == from_ds) return PcqUnsupportedDs;            // need exactly one DS bit (STA<->AP)

    size_t header = 24;
    uint8_t subtype = (f[0] >> 4) & 0x0Fu;
    if(subtype & 0x08u) {                                    // QoS data
        header += 2;
        if(f[1] & 0x80u) header += 4;                        // +HT Control when Order set
    }
    if(len < header + 8) return PcqTruncated;

    const uint8_t* snap = f + header;
    static const uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    if(memcmp(snap, llc, 8) != 0) return PcqNotEapol;        // LLC/SNAP + EAPOL ethertype

    size_t eo = header + 8;
    if(len < eo + 4) return PcqTruncated;
    const uint8_t* e = f + eo;
    if(e[0] < 1 || e[0] > 3) return PcqNotEapol;             // 802.1X protocol version 1..3
    if(e[1] != 3) return PcqNotEapol;                        // 802.1X type must be EAPOL-Key
    size_t body = ((size_t)e[2] << 8) | e[3];
    if(body < 95) return PcqBadEapolLength;
    if(len - eo < body + 4) return PcqBadEapolLength;
    // Key Data Length (big-endian at fixed offset +95) must account for exactly the bytes past the
    // 95-byte fixed EAPOL-Key part: body == 95 + key-data-length. A record whose internal length
    // disagrees with its 802.1X length is malformed (or a truncated/padded capture), not usable.
    uint16_t kdl = ((uint16_t)e[97] << 8) | e[98];
    if((size_t)95 + kdl != body) return PcqBadEapolLength;

    uint8_t desc = e[4];
    if(desc != 2 && desc != 254) return PcqBadKeyDescriptor; // RSN or WPA
    uint16_t ki = ((uint16_t)e[5] << 8) | e[6];
    uint8_t kver = ki & 0x07u;
    if(!(ki & PCQ_KI_PAIRWISE) || kver == 0 || kver > 3 ||
       (ki & (PCQ_KI_ERROR | PCQ_KI_REQUEST | PCQ_KI_SMK)))
        return PcqBadKeyInfo;

    int msg = classify(ki);
    if(msg == 0) return PcqBadKeyInfo;
    // Direction must match the message: M1/M3 travel AP->STA (FromDS), M2/M4 STA->AP (ToDS). We
    // already required exactly one DS bit, so a mismatch here means a spoofed/misclassified frame.
    if((msg == 1 || msg == 3) && !from_ds) return PcqBadKeyInfo;
    if((msg == 2 || msg == 4) && !to_ds) return PcqBadKeyInfo;

    memset(rec, 0, sizeof(*rec));
    rec->message = (uint8_t)msg;
    rec->desc = desc;
    rec->kver = kver;
    memcpy(rec->replay, e + 9, 8);
    memcpy(rec->nonce, e + 17, 32);
    memcpy(rec->mic, e + 81, 16);
    if(to_ds) {                                              // STA -> AP: addr1=BSSID, addr2=STA
        memcpy(rec->bssid, f + 4, 6);
        memcpy(rec->sta, f + 10, 6);
    } else {                                                 // AP -> STA: addr1=STA, addr2=BSSID
        memcpy(rec->bssid, f + 10, 6);
        memcpy(rec->sta, f + 4, 6);
    }

    if(msg <= 3 && degenerate(rec->nonce, 32)) return PcqBadNonce;
    if(msg == 1) {
        if(!bytes_all(rec->mic, 16, 0x00)) return PcqBadMic; // M1 carries no MIC yet
    } else if(degenerate(rec->mic, 16)) {
        return PcqBadMic;
    }
    return PcqAccepted;
}

static void find_pair(PetrelCaptureQuality* q) {
    q->pair = PcqPairNone;
    // Prefer M1+M2: the NEAREST preceding M1 (same STA) stops an old replay value from a prior
    // reconnect being paired across exchanges.
    for(int i = 0; i < q->count; i++) {
        PcqRecord* m2 = &q->records[i];
        if(m2->message != 2) continue;
        PcqRecord* m1 = NULL;
        for(int b = i - 1; b >= 0; b--)
            if(q->records[b].message == 1 && mac_eq(q->records[b].sta, m2->sta) &&
               mac_eq(q->records[b].bssid, m2->bssid)) { m1 = &q->records[b]; break; }
        // A crackable pair must share the key-descriptor family and version: an RSN M1 does not
        // pair with a WPA M2, and mixed key versions are not one exchange.
        if(m1 && replay_eq(m1->replay, m2->replay) &&
           m1->desc == m2->desc && m1->kver == m2->kver) { q->pair = PcqPairM1M2; return; }
    }
    // Fallback M2+M3 with replay+1; if M1 for the exchange exists, M3 must repeat its ANonce.
    for(int i = 0; i < q->count; i++) {
        PcqRecord* m2 = &q->records[i];
        if(m2->message != 2) continue;
        for(int j = i + 1; j < q->count; j++) {
            PcqRecord* m3 = &q->records[j];
            if(m3->message != 3 || !mac_eq(m3->sta, m2->sta) || !mac_eq(m3->bssid, m2->bssid)) continue;
            if(m3->desc != m2->desc || m3->kver != m2->kver) continue;   // same exchange family
            if(!replay_next(m2->replay, m3->replay)) continue;
            PcqRecord* m1 = NULL;
            for(int b = i - 1; b >= 0; b--)                              // nearest M1: SAME (BSSID,STA)
                if(q->records[b].message == 1 && mac_eq(q->records[b].sta, m2->sta) &&
                   mac_eq(q->records[b].bssid, m2->bssid)) { m1 = &q->records[b]; break; }
            if(m1 && replay_eq(m1->replay, m2->replay) && memcmp(m1->nonce, m3->nonce, 32) != 0) continue;
            q->pair = PcqPairM2M3; return;
        }
    }
}

void pcq_reset(PetrelCaptureQuality* q, const uint8_t target_bssid[6]) {
    memset(q, 0, sizeof(*q));
    if(target_bssid) { memcpy(q->target_bssid, target_bssid, 6); q->target_set = true; }
}

PcqIngest pcq_ingest(PetrelCaptureQuality* q, const uint8_t* frame, size_t length) {
    PcqRecord rec;
    PcqIngest r = parse(frame, length, &rec);
    if(r == PcqAccepted) {
        if(q->target_set && !mac_eq(rec.bssid, q->target_bssid)) {
            r = PcqWrongBssid;
        } else {
            bool dup = false;
            for(int i = 0; i < q->count; i++) {              // de-duplicate on full identity
                PcqRecord* o = &q->records[i];
                if(o->message == rec.message && mac_eq(o->bssid, rec.bssid) && mac_eq(o->sta, rec.sta) &&
                   replay_eq(o->replay, rec.replay) && memcmp(o->nonce, rec.nonce, 32) == 0 &&
                   memcmp(o->mic, rec.mic, 16) == 0) { dup = true; break; }
            }
            if(dup) { q->duplicates++; r = PcqDuplicate; }
            else if(q->count >= PCQ_MAX_RECORDS) r = PcqCapacity;
            else {
                q->records[q->count++] = rec;
                q->msg_mask |= (uint16_t)(1u << rec.message);
                find_pair(q);
                r = PcqAccepted;
            }
        }
    }
    q->rejects[(unsigned)r]++;   // per-category tally (failure evidence); r is always a valid 0..11 index
    return r;
}

void pcq_reject_brief(const PetrelCaptureQuality* q, char* out, size_t cap) {
    static const char* name[12] = {
        "", "dup", "not-eapol", "off-target", "bad-ds", "truncated", "bad-eapol-len",
        "bad-descriptor", "bad-keyinfo", "bad-nonce", "bad-mic", "full"};
    int best = -1; uint16_t bestn = 0;
    for(int i = 2; i < 12; i++)                              // skip Accepted(0) and Duplicate(1)
        if(q->rejects[i] > bestn) { bestn = q->rejects[i]; best = i; }
    size_t o = 0;
    if(best > 0)
        for(const char* p = name[best]; *p && o + 1 < cap; ) out[o++] = *p++;
    if(cap) out[o < cap ? o : cap - 1] = 0;
}

void pcq_histogram(const PetrelCaptureQuality* q, char* out, size_t cap) {
    static const char* name[12] = {
        "acc", "dup", "not-eapol", "off-target", "bad-ds", "trunc", "bad-len",
        "bad-desc", "bad-ki", "bad-nonce", "bad-mic", "full"};
    size_t o = 0;
    if(cap) out[0] = 0;
    for(int i = 0; i < 12; i++) {
        uint16_t v = q->rejects[i];
        if(!v) continue;
        if(o && o + 1 < cap) out[o++] = ' ';
        for(const char* p = name[i]; *p && o + 1 < cap; ) out[o++] = *p++;
        if(o + 1 < cap) out[o++] = '=';
        // manual unsigned->decimal (snprintf-free, firmware-TU-safe contract like pcq_summary)
        char d[6];
        int dn = 0;
        if(v == 0) d[dn++] = '0';
        while(v) { d[dn++] = (char)('0' + v % 10); v /= 10; }
        while(dn-- > 0 && o + 1 < cap) out[o++] = d[dn];
    }
    if(cap) out[o < cap ? o : cap - 1] = 0;
}

bool pcq_has_pair(const PetrelCaptureQuality* q) { return q->pair != PcqPairNone; }

void pcq_summary(const PetrelCaptureQuality* q, char* out, size_t cap) {
    bool m1 = q->msg_mask & 0x02, m2 = q->msg_mask & 0x04, m3 = q->msg_mask & 0x08, m4 = q->msg_mask & 0x10;
    const char* verdict = q->pair != PcqPairNone ? "OK"
        : ((m1 && m2) || (m2 && m3))            ? "no valid pair"
        : m1                                     ? "M1 only"
                                                 : "incomplete";
    // manual assembly (snprintf-light contract: the firmware TU's snprintf mangles %-specifiers)
    size_t o = 0;
    #define PUT(s) do{ const char* p=(s); while(*p && o+1<cap) out[o++]=*p++; }while(0)
    if(m1) PUT("M1 ");
    if(m2) PUT("M2 ");
    if(m3) PUT("M3 ");
    if(m4) PUT("M4 ");
    PUT(verdict);
    #undef PUT
    if(cap) out[o < cap ? o : cap - 1] = 0;
}
