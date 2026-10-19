/* petrel_proto_test.c — standalone self-test for the framed transport.
 * Build+run:  cc -I. -Wall -Wextra -o /tmp/dpt common/petrel_proto_test.c && /tmp/dpt
 * No framework: asserts, exits 0 on success. Covers encode/decode roundtrip,
 * CRC-corruption drop, SOF resync over garbage, and oversize-length reject.
 */
#include "petrel_proto.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* capture the last frame the decoder emitted */
typedef struct {
    int calls;
    uint8_t type;
    uint16_t len;
    uint8_t payload[PETREL_MAX_PAYLOAD];
} cap_t;

static void on_frame(uint8_t type, const uint8_t *payload, uint16_t len, void *ctx) {
    cap_t *c = (cap_t *)ctx;
    c->calls++;
    c->type = type;
    c->len = len;
    if (len) memcpy(c->payload, payload, len);
}

static void feed_all(petrel_dec *d, const uint8_t *buf, size_t n, cap_t *c) {
    size_t i;
    for (i = 0; i < n; i++) petrel_dec_feed(d, buf[i], on_frame, c);
}

int main(void) {
    uint8_t out[PETREL_FRAME_MAX];
    petrel_dec d;
    cap_t c;

    /* 1. roundtrip: encode a payload, stream it in, callback must match exactly */
    {
        const uint8_t msg[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11};
        size_t n = petrel_encode(DP_SCAN_AP, msg, sizeof(msg), out);
        assert(n == PETREL_HDR + sizeof(msg) + 2);
        memset(&c, 0, sizeof(c));
        petrel_dec_init(&d);
        feed_all(&d, out, n, &c);
        assert(c.calls == 1);
        assert(c.type == DP_SCAN_AP);
        assert(c.len == sizeof(msg));
        assert(memcmp(c.payload, msg, sizeof(msg)) == 0);
        assert(d.bad == 0);
    }

    /* 1b. zero-length payload frame (len field 0, skips DS_PAYLOAD) */
    {
        size_t n = petrel_encode(DP_CMD_ACK, NULL, 0, out);
        memset(&c, 0, sizeof(c));
        petrel_dec_init(&d);
        feed_all(&d, out, n, &c);
        assert(c.calls == 1 && c.type == DP_CMD_ACK && c.len == 0 && d.bad == 0);
    }

    /* 2. CRC corruption -> dropped, no callback */
    {
        const uint8_t msg[] = {1, 2, 3, 4};
        size_t n = petrel_encode(DP_EVENT, msg, sizeof(msg), out);
        out[PETREL_HDR + 1] ^= 0xFF; /* flip a payload byte after CRC computed */
        memset(&c, 0, sizeof(c));
        petrel_dec_init(&d);
        feed_all(&d, out, n, &c);
        assert(c.calls == 0);
        assert(d.bad == 1);
    }

    /* 3. SOF resync: junk + a false 0xA5 with bad VER, then a clean frame */
    {
        const uint8_t msg[] = {0x42};
        uint8_t stream[64];
        size_t n, k = 0;
        stream[k++] = 0x00;
        stream[k++] = 0xFF;
        stream[k++] = PETREL_SOF; /* false SOF ... */
        stream[k++] = 0x99;      /* ... bad VER -> bad++, back to SOF */
        n = petrel_encode(DP_STATUS, msg, sizeof(msg), out);
        memcpy(stream + k, out, n);
        k += n;
        memset(&c, 0, sizeof(c));
        petrel_dec_init(&d);
        feed_all(&d, stream, k, &c);
        assert(c.calls == 1);
        assert(c.type == DP_STATUS && c.len == 1 && c.payload[0] == 0x42);
        assert(d.bad == 1); /* the false-SOF/bad-VER */
    }

    /* 4a. encode rejects oversize payload */
    {
        assert(petrel_encode(DP_FRAME, out, PETREL_MAX_PAYLOAD + 1, out) == 0);
    }

    /* 4b. decoder rejects an oversize LEN field and resyncs to the next frame */
    {
        const uint8_t msg[] = {0x7E};
        uint8_t stream[16];
        size_t n, k = 0;
        stream[k++] = PETREL_SOF;
        stream[k++] = PETREL_VER;
        stream[k++] = DP_FRAME;
        stream[k++] = 0x01; /* LEN low */
        stream[k++] = 0xFF; /* LEN high -> 0xFF01 > MAX -> bad++, resync */
        n = petrel_encode(DP_CMD, msg, sizeof(msg), out);
        memcpy(stream + k, out, n);
        k += n;
        memset(&c, 0, sizeof(c));
        petrel_dec_init(&d);
        feed_all(&d, stream, k, &c);
        assert(c.calls == 1 && c.type == DP_CMD && c.payload[0] == 0x7E);
        assert(d.bad == 1);
    }

    /* 5. DP_FRAME record: pack (truncated capture) -> encode -> decode -> unpack.
     * origlen=300 (on air) but only caplen=256 captured: host must see both. */
    {
        uint8_t raw[256], rec[PETREL_FRAMEREC_HDR + 256];
        size_t rn, n;
        uint32_t ts;
        uint16_t origlen, caplen, i;
        for (i = 0; i < 256; i++) raw[i] = (uint8_t)i;
        rn = petrel_framerec(0x12345678u, 300, raw, 256, rec);
        assert(rn == PETREL_FRAMEREC_HDR + 256);
        n = petrel_encode(DP_FRAME, rec, (uint16_t)rn, out);
        memset(&c, 0, sizeof(c));
        petrel_dec_init(&d);
        feed_all(&d, out, n, &c);
        assert(c.calls == 1 && c.type == DP_FRAME && c.len == rn && d.bad == 0);
        ts = (uint32_t)c.payload[0] | ((uint32_t)c.payload[1] << 8) |
             ((uint32_t)c.payload[2] << 16) | ((uint32_t)c.payload[3] << 24);
        origlen = (uint16_t)(c.payload[4] | (c.payload[5] << 8));
        caplen = (uint16_t)(c.payload[6] | (c.payload[7] << 8));
        assert(ts == 0x12345678u && origlen == 300 && caplen == 256);
        assert(memcmp(c.payload + PETREL_FRAMEREC_HDR, raw, 256) == 0);
    }

    /* 5b. record packer rejects an oversize capture */
    {
        uint8_t rec[4];
        assert(petrel_framerec(0, 0, rec, (uint16_t)(PETREL_FRAMEREC_MAX_CAP + 1), rec) == 0);
    }

    printf("petrel_proto self-test: OK\n");
    return 0;
}
