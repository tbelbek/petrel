/* wids.h — Petrel passive WIDS detectors (SHARED: BW16 firmware + host self-test).
 *
 * Pure detection logic — no RF, no Arduino types — so every detector is host-unit-testable by
 * replaying synthetic 802.11 frame buffers into it (the firmware NEVER self-transmits to test a
 * detector; that would be an on-air attack). Slice 1: deauth-flood + evil-twin (RSN downgrade).
 *
 * Design (per advisor): fixed slot table, no malloc; rate/window gating (single deauth = roaming,
 * not a flood); evil-twin keyed on RSN DOWNGRADE for a BSSID (SAE->PSK, WPA2->open), NOT
 * "same SSID, new BSSID" — a multi-AP ESS (mesh/enterprise) is many legit BSSIDs sharing an SSID.
 * One radio: the caller parks on a channel; windowed counts only cover that channel.
 */
#ifndef PETREL_WIDS_H
#define PETREL_WIDS_H

#include <stdint.h>
#include <string.h>

#define WIDS_MAX 16                    /* ponytail: fixed 16-slot table, bump if eviction thrashes */
#define WIDS_DEAUTH_WIN_MS 2000u       /* sliding window for the deauth-flood rate */
#define WIDS_DEAUTH_THRESH 20u         /* >= this many deauth/disassoc from one src per window = flood */
#define WIDS_DEBOUNCE_MS 10000u        /* at most one alert per slot per 10 s (anti alert-storm) */
/* slice 2 */
#define WIDS_BFLOOD_WIN_MS 3000u       /* window for the new-BSSID (beacon-flood) rate */
#define WIDS_BFLOOD_THRESH 25u         /* >= this many NEW BSSIDs per window = beacon flood */
#define WIDS_KARMA_CHURN 5u            /* one BSSID advertising >= this many distinct SSIDs = KARMA */

enum { WIDS_SEC_OPEN = 0, WIDS_SEC_WPA2 = 1, WIDS_SEC_WPA3 = 2 }; /* higher = stronger */
enum { WIDS_NONE = 0, WIDS_DEAUTH_FLOOD = 1, WIDS_EVIL_TWIN = 2, WIDS_BEACON_FLOOD = 3, WIDS_KARMA = 4 };

typedef struct {
    uint8_t  key[6];      /* deauth: src MAC; beacon: BSSID */
    uint8_t  used;
    uint8_t  sec_class;   /* beacon: strongest security class ever seen for this BSSID */
    uint8_t  ssid_churn;  /* beacon: distinct-SSID changes on this BSSID (KARMA responder) */
    uint16_t ssid_hash;   /* beacon: FNV-1a16 of SSID */
    uint16_t win_count;   /* deauth: frames in the current window */
    uint32_t win_start;   /* deauth: window start; beacon: reused as last-seen (for LRU) */
    uint32_t last_alert;  /* debounce */
} wids_slot_t;

typedef struct {
    wids_slot_t slot[WIDS_MAX];
    uint32_t seen_frames;
    uint32_t ap_win_start;   /* beacon-flood window start */
    uint16_t ap_new;         /* NEW BSSIDs seen in the current window */
    uint32_t last_flood_alert;
} wids_state;

static void wids_init(wids_state* s) { memset(s, 0, sizeof(*s)); }

static uint16_t wids_ssid_hash(const uint8_t* ssid, uint8_t n) {
    uint16_t h = 0x811c; /* FNV-1a, 16-bit fold */
    uint8_t i;
    for (i = 0; i < n; i++) { h ^= ssid[i]; h = (uint16_t)(h * 0x0101u); }
    return h;
}

/* Find or allocate a slot for a 6-byte key; evict the least-recently-touched when full. Sets
 * *is_new (if non-NULL) to 1 when a slot was freshly allocated for this key. */
static wids_slot_t* wids_slot(wids_state* s, const uint8_t* key, int* is_new) {
    int i, freei = -1, oldest = 0;
    for (i = 0; i < WIDS_MAX; i++) {
        if (s->slot[i].used && !memcmp(s->slot[i].key, key, 6)) { if (is_new) *is_new = 0; return &s->slot[i]; }
        if (!s->slot[i].used && freei < 0) freei = i;
        if (s->slot[i].win_start < s->slot[oldest].win_start) oldest = i;
    }
    i = (freei >= 0) ? freei : oldest;
    memset(&s->slot[i], 0, sizeof(wids_slot_t));
    memcpy(s->slot[i].key, key, 6);
    s->slot[i].used = 1;
    if (is_new) *is_new = 1;
    return &s->slot[i];
}

/* A deauth/disassoc frame from `src` at time `now`. Returns WIDS_DEAUTH_FLOOD (debounced) or 0. */
static int wids_feed_deauth(wids_state* s, const uint8_t* src, uint32_t now) {
    wids_slot_t* sl = wids_slot(s, src, 0);
    if (now - sl->win_start > WIDS_DEAUTH_WIN_MS) { sl->win_start = now; sl->win_count = 0; }
    sl->win_count++;
    if (sl->win_count >= WIDS_DEAUTH_THRESH &&
        (sl->last_alert == 0 || now - sl->last_alert > WIDS_DEBOUNCE_MS)) {
        sl->last_alert = now;
        return WIDS_DEAUTH_FLOOD;
    }
    return WIDS_NONE;
}

/* A beacon/probe-resp for `bssid` (ssid_hash, sec_class) at `now`. Alerts WIDS_EVIL_TWIN when a
 * BSSID that was seen with stronger security now advertises the SAME SSID with weaker security. */
static int wids_feed_beacon(wids_state* s, const uint8_t* bssid, uint16_t ssid_hash,
                            uint8_t sec_class, uint32_t now) {
    int is_new = 0;
    wids_slot_t* sl = wids_slot(s, bssid, &is_new);
    int alert = WIDS_NONE;

    /* beacon-flood: rate of NEW BSSIDs across the environment (beacon spam makes many fake APs). */
    if (is_new) {
        if (now - s->ap_win_start > WIDS_BFLOOD_WIN_MS) { s->ap_win_start = now; s->ap_new = 0; }
        s->ap_new++;
        if (s->ap_new >= WIDS_BFLOOD_THRESH &&
            (s->last_flood_alert == 0 || now - s->last_flood_alert > WIDS_DEBOUNCE_MS)) {
            s->last_flood_alert = now;
            alert = WIDS_BEACON_FLOOD;
        }
    } else if (sl->ssid_hash == ssid_hash) {
        /* same BSSID, same SSID, now weaker security -> evil-twin downgrade (slice 1) */
        if (sl->sec_class > sec_class &&
            (sl->last_alert == 0 || now - sl->last_alert > WIDS_DEBOUNCE_MS)) {
            sl->last_alert = now; alert = WIDS_EVIL_TWIN;
        }
    } else {
        /* same BSSID advertising a DIFFERENT SSID -> churn; a KARMA responder answers probes for
         * many SSIDs from one radio, so a high distinct-SSID count on one BSSID flags it. */
        if (sl->ssid_churn < 255) sl->ssid_churn++;
        if (sl->ssid_churn >= WIDS_KARMA_CHURN &&
            (sl->last_alert == 0 || now - sl->last_alert > WIDS_DEBOUNCE_MS)) {
            sl->last_alert = now; alert = WIDS_KARMA;
        }
    }

    sl->ssid_hash = ssid_hash;
    if (sec_class > sl->sec_class) sl->sec_class = sec_class; /* baseline = strongest ever seen */
    sl->win_start = now;                                     /* last-seen for LRU */
    return alert;
}

/* ---- pure 802.11 beacon/probe-resp parser (raw frame, no FCS) ----
 * Fills bssid[6], *ssid_hash, *sec_class. Returns 1 if the frame is a beacon(8)/probe-resp(5)
 * mgmt frame we could parse, else 0. Mirrors the firmware's pmf_parse RSN walk. */
static int wids_parse_beacon(const uint8_t* f, unsigned len,
                             uint8_t bssid[6], uint16_t* ssid_hash, uint8_t* sec_class) {
    uint8_t ftype, st;
    unsigned i;
    int have_rsn = 0, sae = 0;
    uint16_t sh = 0;
    if (len < 38) return 0;
    ftype = (f[0] >> 2) & 3;
    st = (f[0] >> 4) & 0xF;
    if (ftype != 0 || (st != 8 && st != 5)) return 0; /* mgmt beacon/probe-resp only */
    memcpy(bssid, f + 16, 6);                          /* addr3 = BSSID */
    i = 36;                                            /* 24B mgmt hdr + 12B fixed params */
    while (i + 2 <= len) {
        uint8_t id = f[i], l = f[i + 1];
        unsigned d = i + 2;
        if (d + l > len) break;
        if (id == 0) {                                 /* SSID */
            uint8_t n = l < 32 ? l : 32;
            sh = wids_ssid_hash(f + d, n);
        } else if (id == 48 && l >= 8) {               /* RSN IE */
            unsigned p = d + 2 + 4;                     /* skip version + group cipher suite */
            if (p + 2 <= d + l) {
                uint16_t pc = (uint16_t)(f[p] | (f[p + 1] << 8));
                p += 2 + 4u * pc;                       /* pairwise count + suites */
            }
            if (p + 2 <= d + l) {
                uint16_t ac = (uint16_t)(f[p] | (f[p + 1] << 8));
                unsigned k;
                p += 2;
                for (k = 0; k < ac && p + 4 <= d + l; k++, p += 4)
                    if (f[p + 3] == 8 || f[p + 3] == 9) sae = 1; /* AKM SAE / FT-SAE */
            }
            have_rsn = 1;
        }
        i = d + l;
    }
    *ssid_hash = sh;
    *sec_class = have_rsn ? (sae ? WIDS_SEC_WPA3 : WIDS_SEC_WPA2) : WIDS_SEC_OPEN;
    return 1;
}

#endif /* PETREL_WIDS_H */
