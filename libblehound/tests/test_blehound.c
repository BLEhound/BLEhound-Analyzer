/* test_blehound.c
 * Unit tests for libblehound.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blehound/blehound.h"

static int failures;

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

static void test_cobs_known_vectors(void)
{
    const uint8_t in[] = { 0x11, 0x00, 0x22, 0x33 };
    const uint8_t expect[] = { 0x02, 0x11, 0x03, 0x22, 0x33, 0x00 };
    uint8_t enc[16];
    uint8_t dec[16];
    size_t dec_len;

    size_t n = bh_cobs_encode(in, sizeof(in), enc, sizeof(enc));
    CHECK(n == sizeof(expect));
    CHECK(memcmp(enc, expect, sizeof(expect)) == 0);

    CHECK(bh_cobs_decode(enc, n - 1, dec, sizeof(dec), &dec_len));
    CHECK(dec_len == sizeof(in));
    CHECK(memcmp(dec, in, sizeof(in)) == 0);
}

static void test_cobs_roundtrip_long_runs(void)
{
    /* Exercise the 0xFF (254-byte run) code path and embedded zeros. */
    uint8_t in[600];
    uint8_t enc[700];
    uint8_t dec[600];
    size_t dec_len;

    for (size_t i = 0; i < sizeof(in); i++) {
        in[i] = (uint8_t)(i % 300 == 299 ? 0 : (i % 251) + 1);
    }
    for (size_t len = 0; len <= sizeof(in); len += 37) {
        size_t n = bh_cobs_encode(in, len, enc, sizeof(enc));
        CHECK(n > 0);
        CHECK(memchr(enc, 0, n - 1) == NULL);
        CHECK(enc[n - 1] == 0);
        CHECK(bh_cobs_decode(enc, n - 1, dec, sizeof(dec), &dec_len));
        CHECK(dec_len == len);
        CHECK(memcmp(dec, in, len) == 0);
    }
}

static void test_cobs_rejects_malformed(void)
{
    const uint8_t zero_inside[] = { 0x01, 0x00, 0x01 };   /* zero code byte */
    const uint8_t truncated[] = { 0x05, 0x11 };
    uint8_t out[8];
    size_t out_len;
    uint8_t tiny[1];

    CHECK(!bh_cobs_decode(zero_inside, sizeof(zero_inside), out, sizeof(out), &out_len));
    CHECK(!bh_cobs_decode(truncated, sizeof(truncated), out, sizeof(out), &out_len));
    CHECK(bh_cobs_encode((const uint8_t *)"abc", 3, tiny, sizeof(tiny)) == 0);
}

/* A 1M advertising packet frame: ADV_IND with 6-byte AdvA. */
static size_t make_frame(uint8_t *raw, uint8_t flags, uint8_t phy, bool tri)
{
    const uint8_t pdu[] = { 0x40, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    size_t o = 0;

    raw[o++] = BH_FRAME_PACKET;
    raw[o++] = flags;
    raw[o++] = 0x78; raw[o++] = 0x56; raw[o++] = 0x34; raw[o++] = 0x12;    /* ts */
    raw[o++] = 37;                                                          /* channel */
    raw[o++] = (uint8_t)-60;                                                /* rssi */
    raw[o++] = phy;
    raw[o++] = 0xD6; raw[o++] = 0xBE; raw[o++] = 0x89; raw[o++] = 0x8E;    /* AA */
    raw[o++] = 0xAA; raw[o++] = 0xBB; raw[o++] = 0xCC;                      /* CRC */
    raw[o++] = sizeof(pdu);
    if (tri) {
        raw[o++] = 2;                                                       /* board */
        raw[o++] = 0x01; raw[o++] = 0x00; raw[o++] = 0x00; raw[o++] = 0x00; /* epoch */
    }
    memcpy(raw + o, pdu, sizeof(pdu));
    return o + sizeof(pdu);
}

static void test_parse_frame(void)
{
    uint8_t raw[64];
    bh_packet pkt;
    size_t len = make_frame(raw, 0x01, BH_PHY_1M, false);

    CHECK(bh_parse_frame(raw, len, &pkt));
    CHECK(pkt.ts_us == 0x12345678);
    CHECK(pkt.channel == 37);
    CHECK(pkt.rssi == -60);
    CHECK(pkt.access_addr == 0x8E89BED6);
    CHECK(pkt.crc == 0xCCBBAA);
    CHECK(pkt.crc_ok);
    CHECK(pkt.pdu_len == 8 && pkt.pdu[0] == 0x40);
    CHECK(pkt.board_id == 0);

    len = make_frame(raw, 0x01 | 0x08, BH_PHY_1M, true);
    CHECK(bh_parse_frame(raw, len, &pkt));
    CHECK(pkt.board_id == 2 && pkt.sync_epoch == 1);
    CHECK(pkt.pdu[0] == 0x40);

    /* Length mismatch and wrong type are rejected. */
    CHECK(!bh_parse_frame(raw, len - 1, &pkt));
    raw[0] = 0x02;
    CHECK(!bh_parse_frame(raw, len, &pkt));
    CHECK(!bh_parse_frame(raw, 5, &pkt));
}

static void test_rf_channel(void)
{
    CHECK(bh_ble_to_rf_channel(37) == 0);
    CHECK(bh_ble_to_rf_channel(38) == 12);
    CHECK(bh_ble_to_rf_channel(39) == 39);
    CHECK(bh_ble_to_rf_channel(0) == 1);
    CHECK(bh_ble_to_rf_channel(10) == 11);
    CHECK(bh_ble_to_rf_channel(11) == 13);
    CHECK(bh_ble_to_rf_channel(36) == 38);
}

static void test_btle_rf_record(void)
{
    uint8_t raw[64];
    uint8_t rec[BH_MAX_RECORD_LEN];
    bh_packet pkt;
    const uint8_t expect_1m[] = {
        0x00, 0xC4, 0x00, 0x00, 0xD6, 0xBE, 0x89, 0x8E, 0x13, 0x0C,    /* phdr */
        0xD6, 0xBE, 0x89, 0x8E,                                         /* AA */
        0x40, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,                 /* PDU */
        0xAA, 0xBB, 0xCC,                                               /* CRC */
    };

    CHECK(bh_parse_frame(raw, make_frame(raw, 0x01, BH_PHY_1M, false), &pkt));
    size_t n = bh_btle_rf_record(&pkt, rec, sizeof(rec));
    CHECK(n == sizeof(expect_1m));
    CHECK(memcmp(rec, expect_1m, sizeof(expect_1m)) == 0);

    /* Coded S2: PHY bits = 2, CRC invalid, coding indicator 1 after the AA. */
    CHECK(bh_parse_frame(raw, make_frame(raw, 0x00, BH_PHY_CODED_S2, false), &pkt));
    n = bh_btle_rf_record(&pkt, rec, sizeof(rec));
    CHECK(n == sizeof(expect_1m) + 1);
    CHECK(rec[8] == 0x13 && rec[9] == 0x84);
    CHECK(rec[14] == 1);

    CHECK(bh_btle_rf_record(&pkt, rec, 10) == 0);
}

static void test_ts_mapper_wrap(void)
{
    bh_ts_mapper m;

    bh_ts_mapper_init(&m, 1000000000000ULL);
    CHECK(bh_ts_mapper_map(&m, 0xFFFFFF00) == 1000000000000ULL);
    CHECK(bh_ts_mapper_map(&m, 0xFFFFFFF0) == 1000000000000ULL + 0xF0);
    /* Counter wrapped past zero. */
    CHECK(bh_ts_mapper_map(&m, 0x10) == 1000000000000ULL + 0x110);
}

static void test_cmd_and_mac(void)
{
    uint8_t mac[6];
    uint8_t out[32];
    const uint8_t expect_target[] = { 0x08, 0x84, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    const uint8_t expect_clear[] = { 0x02, 0x84, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00 };
    const uint8_t zeros[6] = { 0 };

    CHECK(bh_parse_mac("11:22:33:44:55:66", mac));
    CHECK(mac[0] == 0x66 && mac[5] == 0x11);
    CHECK(bh_parse_mac(" aa-bb-cc-dd-ee-ff ", mac));
    CHECK(!bh_parse_mac("11:22:33:44:55", mac));
    CHECK(!bh_parse_mac("11:22:33:44:55:6g", mac));
    CHECK(!bh_parse_mac("11:22:33:44:55:66:77", mac));

    CHECK(bh_parse_mac("11:22:33:44:55:66", mac));
    CHECK(bh_cmd_build(BH_CMD_SET_TARGET, mac, 6, out, sizeof(out)) == sizeof(expect_target));
    CHECK(memcmp(out, expect_target, sizeof(expect_target)) == 0);
    CHECK(bh_cmd_build(BH_CMD_SET_TARGET, zeros, 6, out, sizeof(out)) == sizeof(expect_clear));
    CHECK(memcmp(out, expect_clear, sizeof(expect_clear)) == 0);
}

struct frame_log {
    int count;
    size_t last_len;
};

static void count_frames(void *ctx, const uint8_t *frame, size_t len)
{
    struct frame_log *log = ctx;
    (void)frame;
    log->count++;
    log->last_len = len;
}

static void test_deframer(void)
{
    bh_deframer d;
    struct frame_log log = { 0, 0 };
    uint8_t raw[64];
    uint8_t enc[80];
    uint8_t junk[BH_MAX_ENCODED_LEN + 10];
    size_t raw_len = make_frame(raw, 0x01, BH_PHY_1M, false);
    size_t n = bh_cobs_encode(raw, raw_len, enc, sizeof(enc));

    bh_deframer_init(&d);
    /* Frame split across two reads, preceded by an empty frame. */
    bh_deframer_feed(&d, (const uint8_t *)"\0", 1, count_frames, &log);
    bh_deframer_feed(&d, enc, 5, count_frames, &log);
    bh_deframer_feed(&d, enc + 5, n - 5, count_frames, &log);
    CHECK(log.count == 1 && log.last_len == raw_len);

    /* An oversize frame is dropped and the next frame still decodes. */
    memset(junk, 0x01, sizeof(junk));
    bh_deframer_feed(&d, junk, sizeof(junk), count_frames, &log);
    bh_deframer_feed(&d, (const uint8_t *)"\0", 1, count_frames, &log);
    CHECK(d.bad_frames == 1);
    bh_deframer_feed(&d, enc, n, count_frames, &log);
    CHECK(log.count == 2);
}

static void test_pcap_headers(void)
{
    uint8_t g[BH_PCAP_GLOBAL_HEADER_LEN];
    uint8_t r[BH_PCAP_RECORD_HEADER_LEN];

    bh_pcap_global_header(g);
    CHECK(g[0] == 0xD4 && g[3] == 0xA1 && g[20] == 0x00 && g[21] == 0x01);
    bh_pcap_record_header(1700000000123456ULL, 25, r);
    CHECK(r[4] == 0x40 && r[5] == 0xE2 && r[6] == 0x01);    /* 123456 µs */
    CHECK(r[8] == 25 && r[12] == 25);
}

int main(void)
{
    test_cobs_known_vectors();
    test_cobs_roundtrip_long_runs();
    test_cobs_rejects_malformed();
    test_parse_frame();
    test_rf_channel();
    test_btle_rf_record();
    test_ts_mapper_wrap();
    test_cmd_and_mac();
    test_deframer();
    test_pcap_headers();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("libblehound: all tests passed\n");
    return EXIT_SUCCESS;
}
