/* petrel_proto.h — Petrel v2 framed binary transport (SHARED: BW16 firmware + Flipper FAP)
 *
 * One frame format over BOTH links (Serial1 control, CH340 bulk). Length-prefixed (no byte
 * stuffing) so a reader consumes exactly LEN bytes — the parser is bounded, which retires the
 * old unbounded ASCII line-buffering (an OOM sink on the ~19 KB FAP heap).
 *
 *   +-----+-----+------+-----------+-----------+--------+
 *   | SOF | VER | TYPE | LEN (u16) |  PAYLOAD  | CRC16  |
 *   |0xA5 | 01  | 1B   |  LE, <=1k | LEN bytes | LE     |
 *   +-----+-----+------+-----------+-----------+--------+
 *   CRC16-CCITT (poly 0x1021, init 0xFFFF) over SOF..last payload byte.
 *
 * Header-only, C89-compatible (compiles in Arduino C++ and the FAP's C). No allocation.
 */
#ifndef PETREL_PROTO_H
#define PETREL_PROTO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define PETREL_SOF 0xA5u
#define PETREL_VER 0x01u
#define PETREL_MAX_PAYLOAD 1024u
#define PETREL_HDR 5u /* SOF + VER + TYPE + LEN(2) */
#define PETREL_FRAME_MAX (PETREL_HDR + PETREL_MAX_PAYLOAD + 2u) /* + CRC16 */

/* Frame types. 0x01 CMD wraps the legacy ASCII command path for a zero-regression migration;
 * new features are their own types. */
enum {
    DP_CMD = 0x01,        /* host->board: ASCII command line (e.g. "SCAN\n") */
    DP_CMD_ACK = 0x02,    /* board->host: "ok"/"err ..." text */
    DP_SCAN_AP = 0x10,    /* board->FAP: one scanned AP (binary) */
    DP_SCAN_STA = 0x11,   /* board->FAP: one station */
    DP_FRAME = 0x20,      /* board->host: pcap record, layout PETREL_FRAMEREC (see below) */
    DP_FRAME_DROP = 0x21, /* board->host: dropped frame count (u32 LE) since last report */
    DP_EVENT = 0x30,      /* board->FAP: handshake/pmkid/creds captured, etc. */
    DP_WIDS_ALERT = 0x40, /* board->FAP: passive detection (deauth-flood/rogue-AP/karma...) */
    DP_STATUS = 0x50      /* board->FAP: heap, ring fill, FSM state */
};

/* CRC16-CCITT (0x1021, init 0xFFFF), big-endian shift. */
static inline uint16_t petrel_crc16(const uint8_t *d, size_t n) {
    uint16_t c = 0xFFFFu;
    size_t i;
    int b;
    for (i = 0; i < n; i++) {
        c = (uint16_t)(c ^ ((uint16_t)d[i] << 8));
        for (b = 0; b < 8; b++)
            c = (c & 0x8000u) ? (uint16_t)((c << 1) ^ 0x1021u) : (uint16_t)(c << 1);
    }
    return c;
}

/* Encode a frame into out (>= PETREL_FRAME_MAX). Returns total bytes, or 0 on bad length. */
static inline size_t petrel_encode(uint8_t type, const uint8_t *payload, uint16_t len, uint8_t *out) {
    size_t i = 0;
    uint16_t crc;
    uint16_t j;
    if (len > PETREL_MAX_PAYLOAD) return 0;
    out[i++] = PETREL_SOF;
    out[i++] = PETREL_VER;
    out[i++] = type;
    out[i++] = (uint8_t)(len & 0xFFu);
    out[i++] = (uint8_t)(len >> 8);
    for (j = 0; j < len; j++) out[i++] = payload[j];
    crc = petrel_crc16(out, i); /* over SOF..payload */
    out[i++] = (uint8_t)(crc & 0xFFu);
    out[i++] = (uint8_t)(crc >> 8);
    return i;
}

/* ---- DP_FRAME record (the payload of a DP_FRAME frame) ----
 * ts(u32 LE) | origlen(u16 LE) | caplen(u16 LE) | raw[caplen]
 * origlen = on-air frame length; caplen = bytes actually captured (<=origlen when the
 * board truncates to its slot size). Maps to pcap len/caplen so truncation is visible,
 * not guessed. Shared by board (packer) and host/FAP (same layout) — one source. */
#define PETREL_FRAMEREC_HDR 8u
#define PETREL_FRAMEREC_MAX_CAP (PETREL_MAX_PAYLOAD - PETREL_FRAMEREC_HDR)

/* Pack a DP_FRAME record into rec_out (>= PETREL_FRAMEREC_HDR + caplen). Returns record
 * length, or 0 if caplen would overflow a frame payload. */
static inline size_t petrel_framerec(uint32_t ts, uint16_t origlen, const uint8_t *raw,
                             uint16_t caplen, uint8_t *rec_out) {
    uint16_t i;
    if (caplen > PETREL_FRAMEREC_MAX_CAP) return 0;
    rec_out[0] = (uint8_t)(ts & 0xFFu);
    rec_out[1] = (uint8_t)((ts >> 8) & 0xFFu);
    rec_out[2] = (uint8_t)((ts >> 16) & 0xFFu);
    rec_out[3] = (uint8_t)((ts >> 24) & 0xFFu);
    rec_out[4] = (uint8_t)(origlen & 0xFFu);
    rec_out[5] = (uint8_t)(origlen >> 8);
    rec_out[6] = (uint8_t)(caplen & 0xFFu);
    rec_out[7] = (uint8_t)(caplen >> 8);
    for (i = 0; i < caplen; i++) rec_out[PETREL_FRAMEREC_HDR + i] = raw[i];
    return (size_t)PETREL_FRAMEREC_HDR + caplen;
}

/* ---- streaming decoder: feed bytes, get a callback per valid frame ---- */

typedef void (*petrel_frame_cb)(uint8_t type, const uint8_t *payload, uint16_t len, void *ctx);

enum { DS_SOF = 0, DS_VER, DS_TYPE, DS_LEN0, DS_LEN1, DS_PAYLOAD, DS_CRC0, DS_CRC1 };

typedef struct {
    uint8_t st;
    uint8_t type;
    uint16_t len, got;
    uint16_t crc_rx;
    uint8_t buf[PETREL_HDR + PETREL_MAX_PAYLOAD]; /* SOF..payload, for CRC check */
    size_t bi;
    uint32_t bad; /* frames dropped: CRC fail / bad VER / oversize (resync) */
} petrel_dec;

static inline void petrel_dec_init(petrel_dec *d) { memset(d, 0, sizeof(*d)); }

/* Feed one byte. On a complete, CRC-valid frame, calls cb. Self-resynchronises on garbage. */
static inline void petrel_dec_feed(petrel_dec *d, uint8_t b, petrel_frame_cb cb, void *ctx) {
    switch (d->st) {
    case DS_SOF:
        if (b == PETREL_SOF) {
            d->bi = 0;
            d->buf[d->bi++] = b;
            d->st = DS_VER;
        }
        break;
    case DS_VER:
        if (b != PETREL_VER) { d->bad++; d->st = DS_SOF; break; }
        d->buf[d->bi++] = b;
        d->st = DS_TYPE;
        break;
    case DS_TYPE:
        d->type = b;
        d->buf[d->bi++] = b;
        d->st = DS_LEN0;
        break;
    case DS_LEN0:
        d->len = b;
        d->buf[d->bi++] = b;
        d->st = DS_LEN1;
        break;
    case DS_LEN1:
        d->len |= (uint16_t)b << 8;
        d->buf[d->bi++] = b;
        if (d->len > PETREL_MAX_PAYLOAD) { d->bad++; d->st = DS_SOF; break; } /* resync */
        d->got = 0;
        d->st = d->len ? DS_PAYLOAD : DS_CRC0;
        break;
    case DS_PAYLOAD:
        d->buf[d->bi++] = b;
        if (++d->got >= d->len) d->st = DS_CRC0;
        break;
    case DS_CRC0:
        d->crc_rx = b;
        d->st = DS_CRC1;
        break;
    case DS_CRC1:
        d->crc_rx |= (uint16_t)b << 8;
        if (d->crc_rx == petrel_crc16(d->buf, d->bi)) {
            if (cb) cb(d->type, d->buf + PETREL_HDR, d->len, ctx);
        } else {
            d->bad++;
        }
        d->st = DS_SOF;
        break;
    default:
        d->st = DS_SOF;
        break;
    }
}

#endif /* PETREL_PROTO_H */
