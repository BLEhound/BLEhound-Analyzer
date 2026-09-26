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

/* ------------------------------------------------ multi-board aggregation */

static void test_sync_clock(void)
{
    bh_sync_clock c;
    uint32_t v;

    bh_sync_clock_init(&c, 0, BH_SYNC_PAIR_WINDOW_US);
    bh_sync_clock_observe(&c, 0, 1000, BH_NO_HOST_TIME);
    bh_sync_clock_observe(&c, 1, 4000, BH_NO_HOST_TIME);     /* board 1 runs 3000 ahead */
    CHECK(bh_sync_clock_offset(&c, 1, &v) && v == 3000);
    CHECK(bh_sync_clock_to_ref(&c, 1, 4500, &v) && v == 1500);
    CHECK(bh_sync_clock_to_ref(&c, 0, 1234, &v) && v == 1234);
    CHECK(!bh_sync_clock_to_ref(&c, 2, 10, &v));

    /* Offsets survive the counter wrapping. */
    bh_sync_clock_init(&c, 0, BH_SYNC_PAIR_WINDOW_US);
    bh_sync_clock_observe(&c, 0, 100, BH_NO_HOST_TIME);
    bh_sync_clock_observe(&c, 1, 50, BH_NO_HOST_TIME);
    CHECK(bh_sync_clock_to_ref(&c, 1, 60, &v) && v == 110);
}

static void test_sync_clock_pairing(void)
{
    /* Reports of the same edge arrive on separate serial ports; when board
     * 1's new edge arrives before board 0's it must not be paired with
     * board 0's previous edge (that would be off by one heartbeat). */
    bh_sync_clock c;
    uint32_t v;

    bh_sync_clock_init(&c, 0, BH_SYNC_PAIR_WINDOW_US);
    bh_sync_clock_observe(&c, 0, 1000000, 10000000);
    bh_sync_clock_observe(&c, 1, 4000000, 10200000);        /* edge k: offset 3 s */
    CHECK(bh_sync_clock_offset(&c, 1, &v) && v == 3000000);
    bh_sync_clock_observe(&c, 1, 5000000, 11050000);        /* edge k+1, board 1 first */
    CHECK(bh_sync_clock_offset(&c, 1, &v) && v == 3000000);
    bh_sync_clock_observe(&c, 0, 2000000, 11300000);
    CHECK(bh_sync_clock_offset(&c, 1, &v) && v == 3000000);
    bh_sync_clock_observe(&c, 0, 3000000, 12100000);        /* edge k+2, board 0 first */
    bh_sync_clock_observe(&c, 1, 6000050, 12350000);        /* 50 µs jitter: newest pair wins */
    CHECK(bh_sync_clock_offset(&c, 1, &v) && v == 3000050);
}

static bh_agg_packet mk_pkt(uint8_t board, uint32_t ts, uint32_t sync_epoch,
                            uint32_t aa, uint32_t crc, const uint8_t *pdu, uint8_t len)
{
    bh_agg_packet p;

    memset(&p, 0, sizeof(p));
    p.board_id = board;
    p.ts_us = ts;
    p.sync_epoch = sync_epoch;
    p.access_addr = aa;
    p.crc = crc;
    p.channel = 37;
    p.rssi = -50;
    p.crc_ok = true;
    p.host_us = BH_NO_HOST_TIME;
    p.pdu_len = len;
    memcpy(p.pdu, pdu, len);
    return p;
}

struct agg_log {
    int count;
    bh_agg_packet out[16];
};

static void collect(void *ctx, const bh_agg_packet *pkt)
{
    struct agg_log *log = ctx;
    if (log->count < 16) {
        log->out[log->count] = *pkt;
    }
    log->count++;
}

static void test_aggregate(void)
{
    const uint8_t pdu[] = { 0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const uint8_t pdu2[] = { 0x02, 0x06, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44 };
    struct agg_log log = { 0 };
    bh_aggregator *agg = bh_aggregator_new(200, 5000, 0);
    bh_agg_packet p;

    /* Same SYNC edge: board 0 tick 1000, board 1 tick 4000 -> offset 3000.
     * The same air packet heard by both: aligned 2000 on both. */
    p = mk_pkt(0, 2000, 1000, 0xAABBCCDD, 0x123456, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    p = mk_pkt(1, 5000, 4000, 0xAABBCCDD, 0x123456, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    p = mk_pkt(0, 20000, 1000, 0xAABBCCDD, 0x654321, pdu2, sizeof(pdu2));
    bh_aggregator_add(agg, &p, collect, &log);
    bh_aggregator_flush(agg, collect, &log);
    CHECK(log.count == 2);
    CHECK(log.out[0].crc == 0x123456 && log.out[1].crc == 0x654321);
    CHECK(log.out[0].aligned <= log.out[1].aligned);
    bh_aggregator_free(agg);

    /* No sync_epoch at all still emits. */
    const uint8_t empty[] = { 0, 0 };
    memset(&log, 0, sizeof(log));
    agg = bh_aggregator_new(BH_AGG_DEDUP_US, BH_AGG_REORDER_US, 0);
    p = mk_pkt(1, 500, 0, 0x11111111, 1, empty, sizeof(empty));
    bh_aggregator_add(agg, &p, collect, &log);
    bh_aggregator_flush(agg, collect, &log);
    CHECK(log.count == 1);
    bh_aggregator_free(agg);
}

static void test_hold_until_synced(void)
{
    /* A non-reference board's packets are held until its offset is known,
     * otherwise raw ticks leak into the aligned stream and it jumps. */
    const uint8_t pdu[] = { 0x02, 0x06, 1, 2, 3, 4, 5, 6 };
    struct agg_log log = { 0 };
    bh_aggregator *agg = bh_aggregator_new(200, 5000, 0);
    bh_agg_packet p;

    p = mk_pkt(1, 5000, 0, 0xAABBCCDD, 1, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    CHECK(log.count == 0);
    p = mk_pkt(0, 2000, 1000, 0xAABBCCDD, 2, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    p = mk_pkt(1, 6000, 4000, 0xAABBCCDD, 3, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    bh_aggregator_flush(agg, collect, &log);
    CHECK(log.count == 3);
    CHECK(log.out[0].aligned == 2000 && log.out[1].aligned == 2000 && log.out[2].aligned == 3000);
    CHECK(log.out[0].board_id == 0 && log.out[1].board_id == 1);
    for (int i = 0; i < log.count; i++) {
        CHECK(log.out[i].key64 < (1ull << 32));
    }
    bh_aggregator_free(agg);

    /* Never any SYNC: after the timeout, degrade to raw ticks. */
    memset(&log, 0, sizeof(log));
    agg = bh_aggregator_new(BH_AGG_DEDUP_US, BH_AGG_REORDER_US, 0);
    p = mk_pkt(1, 100, 0, 0xAABBCCDD, 1, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    CHECK(log.count == 0);
    p = mk_pkt(1, 100 + 3100000, 0, 0xAABBCCDD, 2, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    bh_aggregator_flush(agg, collect, &log);
    CHECK(log.count == 2);
    bh_aggregator_free(agg);
}

static void test_reorder_window(void)
{
    const uint8_t pdu[] = { 0x02, 0x06, 9, 9, 9, 9, 9, 9 };
    struct agg_log log = { 0 };
    bh_aggregator *agg = bh_aggregator_new(BH_AGG_DEDUP_US, 300000, 0);
    bh_agg_packet p;

    CHECK(BH_AGG_REORDER_US >= 200000);
    p = mk_pkt(0, 1000000, 1000, 0x11223344, 1, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    p = mk_pkt(0, 1100000, 1000, 0x11223344, 2, pdu, sizeof(pdu));
    bh_aggregator_add(agg, &p, collect, &log);
    p = mk_pkt(0, 1050000, 1000, 0x11223344, 3, pdu, sizeof(pdu));     /* 50 ms late */
    bh_aggregator_add(agg, &p, collect, &log);
    CHECK(log.count == 0);
    bh_aggregator_flush(agg, collect, &log);
    CHECK(log.count == 3);
    CHECK(log.out[0].aligned == 1000000 && log.out[1].aligned == 1050000 && log.out[2].aligned == 1100000);
    bh_aggregator_free(agg);
}

static void test_guard_channel(void)
{
    uint8_t ch;

    CHECK(bh_guard_channel_for_board(0, &ch) && ch == 37);
    CHECK(bh_guard_channel_for_board(1, &ch) && ch == 38);
    CHECK(bh_guard_channel_for_board(2, &ch) && ch == 39);
    CHECK(!bh_guard_channel_for_board(3, &ch));
    CHECK(!bh_guard_channel_for_board(255, &ch));
}

struct relay_log {
    int count;
    uint8_t board[8];
    uint8_t params[8][BH_FOLLOW_PARAMS_LEN];
};

static bool record_send(void *ctx, uint8_t board, const uint8_t *params, size_t len)
{
    struct relay_log *log = ctx;
    if (len != BH_FOLLOW_PARAMS_LEN || log->count >= 8) {
        return false;
    }
    log->board[log->count] = board;
    memcpy(log->params[log->count], params, len);
    log->count++;
    return true;
}

static void test_follow_relay(void)
{
    bh_follow_relay relay;
    struct relay_log log = { 0 };
    uint8_t pdu[2 + 34];
    uint8_t *ll = pdu + 14;
    bh_packet pkt;
    bh_connect_ind ci;
    uint32_t v;

    bh_follow_relay_init(&relay, 0, NULL);
    bh_follow_relay_register(&relay, 0);
    bh_follow_relay_register(&relay, 1);
    bh_follow_relay_register(&relay, 2);
    bh_follow_relay_observe(&relay, 0, 1000, 10000000);
    bh_follow_relay_observe(&relay, 1, 1500, 10010000);      /* +500 */
    bh_follow_relay_observe(&relay, 2, 800, 10020000);       /* -200 */
    CHECK(bh_sync_clock_offset(&relay.clock, 1, &v) && v == 500);
    CHECK(bh_sync_clock_offset(&relay.clock, 2, &v) && v == (uint32_t)(800 - 1000));

    /* CONNECT_IND from board 0: InitA 01..06, AdvA aa..ff. */
    memset(pdu, 0, sizeof(pdu));
    pdu[0] = 0x05;
    pdu[1] = 34;
    for (int i = 0; i < 6; i++) {
        pdu[2 + i] = (uint8_t)(1 + i);
    }
    memcpy(pdu + 8, "\xaa\xbb\xcc\xdd\xee\xff", 6);
    ll[0] = 0x78; ll[1] = 0x56; ll[2] = 0x34; ll[3] = 0x12;      /* AA */
    ll[4] = 0xEF; ll[5] = 0xCD; ll[6] = 0xAB;                    /* crc_init */
    ll[7] = 3;                                                   /* win_size */
    ll[8] = 8;                                                   /* win_offset */
    ll[10] = 24;                                                 /* interval */
    ll[14] = 200;                                                /* timeout */
    memset(ll + 16, 0xFF, 4); ll[20] = 0x1F;                     /* chan_map */
    ll[21] = 0x05;                                               /* hop */

    memset(&pkt, 0, sizeof(pkt));
    pkt.access_addr = BH_ADV_ACCESS_ADDR;
    pkt.channel = 37;
    pkt.ts_us = 100000;
    pkt.pdu = pdu;
    pkt.pdu_len = sizeof(pdu);
    CHECK(bh_is_connect_ind(&pkt));
    CHECK(bh_parse_connect_ind(pdu, sizeof(pdu), &ci));
    CHECK(ci.aa == 0x12345678 && ci.crc_init == 0xABCDEF);
    CHECK(ci.interval == 24 && ci.win_offset == 8 && ci.hop == 5 && !ci.csa2);
    CHECK(memcmp(ci.adva, "\xaa\xbb\xcc\xdd\xee\xff", 6) == 0);

    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10050000, record_send, &log) == 2);
    CHECK(log.count == 2);
    uint32_t air = (2 + 34 + 3) * 8;
    uint32_t anchor0 = 100000 + air + 1250 + 8 * 1250;
    for (int i = 0; i < log.count; i++) {
        const uint8_t *pr = log.params[i];
        uint32_t got = (uint32_t)pr[21] | (uint32_t)pr[22] << 8 | (uint32_t)pr[23] << 16 | (uint32_t)pr[24] << 24;
        uint32_t expect = log.board[i] == 1 ? anchor0 + 500 : anchor0 - 200;
        CHECK(got == expect);
        CHECK(pr[0] == 0x78 && pr[3] == 0x12);                  /* aa */
        CHECK((pr[14] | pr[15] << 8) == 24);                    /* interval */
    }

    /* Same AA within the TTL is not relayed again. */
    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10060000, record_send, &log) == 0);
    CHECK(relay.stats.skipped_dup == 1);

    /* A board whose offset is unknown is skipped. */
    bh_follow_relay_init(&relay, 0, NULL);
    bh_follow_relay_register(&relay, 0);
    bh_follow_relay_register(&relay, 1);
    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10050000, record_send, &log) == 0);
    CHECK(relay.stats.skipped_no_offset == 1);

    /* Target filter: only the wanted AdvA is relayed. */
    bh_follow_relay_init(&relay, 0, (const uint8_t *)"\x01\x02\x03\x04\x05\x06");
    bh_follow_relay_register(&relay, 0);
    bh_follow_relay_register(&relay, 1);
    bh_follow_relay_observe(&relay, 0, 1000, 10000000);
    bh_follow_relay_observe(&relay, 1, 1500, 10010000);
    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10050000, record_send, &log) == 0);
    CHECK(relay.stats.skipped_target == 1);

    /* AUX_CONNECT_REQ on a data channel is not a CONNECT_IND. */
    pkt.channel = 5;
    CHECK(!bh_is_connect_ind(&pkt));
}

static void test_ts_mapper_mono(void)
{
    bh_ts_mapper m;

    bh_ts_mapper_init(&m, 1000000000000ULL);
    CHECK(bh_ts_mapper_map_mono(&m, 5000) == 1000000000000LL);
    CHECK(bh_ts_mapper_map_mono(&m, 6000) == 1000000001000LL);
    /* A late packet steps back, it is not a wrap. */
    CHECK(bh_ts_mapper_map_mono(&m, 4000) == 999999999000LL);
}

/* ----------------------------------------------------------- advertising */

static void test_adv_parse(void)
{
    bh_packet pkt;
    bh_adv_info info;
    char text[18];
    /* ADV_IND, random AdvA, AD: flags, complete name "Ring", manufacturer 0x0059 */
    uint8_t adv_ind[] = {
        0x40, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0xC6,
        0x02, 0x01, 0x06,
        0x05, 0x09, 'R', 'i', 'n', 'g',
        0x04, 0xFF, 0x59, 0x00, 0x11,
    };

    memset(&pkt, 0, sizeof(pkt));
    pkt.access_addr = BH_ADV_ACCESS_ADDR;
    pkt.pdu = adv_ind;
    pkt.pdu_len = sizeof(adv_ind);
    CHECK(bh_adv_parse(&pkt, &info));
    CHECK(info.pdu_type == 0 && info.connectable && info.from_advertiser && !info.extended);
    CHECK(info.adva_random && info.adva[0] == 0x01 && info.adva[5] == 0xC6);
    CHECK(info.has_name && info.name_complete && strcmp(info.name, "Ring") == 0);
    CHECK(info.has_company && info.company_id == 0x0059);
    CHECK(bh_addr_kind(info.adva, true) == BH_ADDR_RANDOM_STATIC);
    bh_format_mac(info.adva, text);
    CHECK(strcmp(text, "C6:05:04:03:02:01") == 0);

    /* Short name is kept until a complete one shows up. */
    uint8_t short_name[] = { 0x02, 0x0A, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x03, 0x08, 'A', 'b' };
    pkt.pdu = short_name;
    pkt.pdu_len = sizeof(short_name);
    CHECK(bh_adv_parse(&pkt, &info));
    CHECK(info.has_name && !info.name_complete && strcmp(info.name, "Ab") == 0);
    CHECK(!info.connectable);
    CHECK(bh_addr_kind(info.adva, false) == BH_ADDR_PUBLIC);

    /* CONNECT_IND: the advertiser is the second address, RxAdd says random. */
    uint8_t connect_ind[2 + 34] = { 0x85, 34, 1, 1, 1, 1, 1, 1, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    pkt.pdu = connect_ind;
    pkt.pdu_len = sizeof(connect_ind);
    CHECK(bh_adv_parse(&pkt, &info));
    CHECK(!info.from_advertiser && info.adva_random && info.adva[0] == 0x10 && info.adva[5] == 0x60);
    CHECK(bh_addr_kind(info.adva, true) == BH_ADDR_RANDOM_RESOLVABLE);

    /* AUX_ADV_IND (type 7): ext header with AdvA, then AdvData with a name. */
    uint8_t aux_adv[] = {
        0x47, 0x0E,
        0x47 /* ext len 7, mode connectable */, 0x01 /* flags: AdvA */,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x05, 0x09, 'C', 'o', 'd', 'e',
    };
    pkt.pdu = aux_adv;
    pkt.pdu_len = sizeof(aux_adv);
    CHECK(bh_adv_parse(&pkt, &info));
    CHECK(info.extended && info.connectable && info.adva[0] == 0x0A);
    CHECK(info.has_name && strcmp(info.name, "Code") == 0);

    /* ADV_EXT_IND without AdvA in the header: nothing to identify. */
    uint8_t ext_no_adva[] = { 0x07, 0x03, 0x02, 0x10, 0x00 };
    pkt.pdu = ext_no_adva;
    pkt.pdu_len = sizeof(ext_no_adva);
    CHECK(!bh_adv_parse(&pkt, &info));

    /* Not on the advertising access address. */
    pkt.pdu = adv_ind;
    pkt.pdu_len = sizeof(adv_ind);
    pkt.access_addr = 0x12345678;
    CHECK(!bh_adv_parse(&pkt, &info));

    /* Truncated AD structure does not read past the end. */
    uint8_t truncated[] = { 0x00, 0x09, 1, 2, 3, 4, 5, 6, 0x09, 0x09, 'x' };
    pkt.access_addr = BH_ADV_ACCESS_ADDR;
    pkt.pdu = truncated;
    pkt.pdu_len = sizeof(truncated);
    CHECK(bh_adv_parse(&pkt, &info));
    CHECK(!info.has_name);
}

static void test_aes_and_rpa(void)
{
    /* FIPS-197 C.1 */
    const uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const uint8_t in[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const uint8_t expect[16] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    uint8_t out[16];

    bh_aes128_encrypt(key, in, out);
    CHECK(memcmp(out, expect, 16) == 0);

    /* BT Core Spec Vol 3 Part H D.7: IRK ec02..7d9b (MSO first), prand 708194 -> hash 0dfbaa */
    uint8_t irk_le[16];
    uint8_t rpa[6];

    CHECK(bh_parse_hex("9b7d390aa61010340 5adc857a33402ec", irk_le, 16) == false); /* stray space inside a byte */
    CHECK(bh_parse_hex("9b7d390aa6101034 05adc857a33402ec", irk_le, 16));
    CHECK(bh_parse_mac("70:81:94:0D:FB:AA", rpa));
    CHECK(bh_rpa_is_resolvable(rpa));
    CHECK(bh_rpa_matches(irk_le, rpa));
    rpa[0] ^= 1;
    CHECK(!bh_rpa_matches(irk_le, rpa));

    /* Real device (2026-09-26): ring IRK wire/LSO-first and an RPA captured over the air. */
    uint8_t ring_irk[16];
    uint8_t ring_rpa[6];
    uint8_t ring_id[6];

    CHECK(bh_parse_hex("2959AE60144E6314AC2D86446CD4344F", ring_irk, 16));
    CHECK(bh_parse_mac("77:67:D0:0A:10:48", ring_rpa));
    CHECK(bh_parse_mac("02:10:F9:56:78:90", ring_id));
    CHECK(bh_rpa_matches(ring_irk, ring_rpa));
    CHECK(!bh_rpa_is_resolvable(ring_id));
    CHECK(!bh_rpa_matches(ring_irk, ring_id));

    /* Wrong byte order must not resolve. */
    uint8_t ring_irk_mso[16];
    for (int i = 0; i < 16; i++) {
        ring_irk_mso[i] = ring_irk[15 - i];
    }
    CHECK(!bh_rpa_matches(ring_irk_mso, ring_rpa));

    CHECK(!bh_parse_hex("2959AE60", ring_irk, 16));
    CHECK(!bh_parse_hex("2959AE60144E6314AC2D86446CD4344F00", ring_irk, 16));
    CHECK(!bh_parse_hex("zz59AE60144E6314AC2D86446CD4344F", ring_irk, 16));
}

static void test_follow_relay_irk(void)
{
    bh_follow_relay relay;
    struct relay_log log = { 0 };
    uint8_t pdu[2 + 34];
    uint8_t *ll = pdu + 14;
    bh_packet pkt;
    uint8_t irk[16];
    uint8_t rpa[6];
    uint8_t other[6];

    CHECK(bh_parse_hex("2959AE60144E6314AC2D86446CD4344F", irk, 16));
    CHECK(bh_parse_mac("77:67:D0:0A:10:48", rpa));
    CHECK(bh_parse_mac("5A:11:22:33:44:55", other));

    /* Target is a stale (already rotated) address; only the IRK links the new one. */
    uint8_t stale[6] = { 1, 2, 3, 4, 5, 0x4A };
    bh_follow_relay_init(&relay, 0, stale);
    bh_follow_relay_set_irk(&relay, irk);
    bh_follow_relay_register(&relay, 0);
    bh_follow_relay_register(&relay, 1);
    bh_follow_relay_observe(&relay, 0, 1000, 10000000);
    bh_follow_relay_observe(&relay, 1, 1500, 10010000);

    memset(pdu, 0, sizeof(pdu));
    pdu[0] = 0x05;
    pdu[1] = 34;
    memcpy(pdu + 2 + 6, rpa, 6);
    ll[0] = 0x11; ll[1] = 0x22; ll[2] = 0x33; ll[3] = 0x44;        /* AA */
    ll[7] = 1;                                                      /* win size */
    ll[8] = 0; ll[9] = 0;                                           /* win offset */
    ll[10] = 24; ll[11] = 0;                                        /* interval */
    ll[14] = 200; ll[15] = 0;                                       /* timeout */
    ll[16] = 0xff; ll[17] = 0xff; ll[18] = 0xff; ll[19] = 0xff; ll[20] = 0x1f;
    ll[21] = 0x0A;                                                  /* hop 10, sca 0 */

    memset(&pkt, 0, sizeof(pkt));
    pkt.access_addr = BH_ADV_ACCESS_ADDR;
    pkt.crc_ok = true;
    pkt.pdu = pdu;
    pkt.pdu_len = sizeof(pdu);
    pkt.channel = 37;
    pkt.ts_us = 2000;

    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10030000, record_send, &log) == 1);
    CHECK(relay.stats.skipped_target == 0);

    /* Another device's RPA is still skipped. */
    memcpy(pdu + 2 + 6, other, 6);
    ll[0] = 0x55;
    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10040000, record_send, &log) == 0);
    CHECK(relay.stats.skipped_target == 1);

    bh_follow_relay_set_irk(&relay, NULL);
    memcpy(pdu + 2 + 6, rpa, 6);
    ll[0] = 0x66;
    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10050000, record_send, &log) == 0);
    CHECK(relay.stats.skipped_target == 2);

    /* Trusting the catching board skips the address check altogether. */
    bh_follow_relay_set_trust(&relay, true);
    memcpy(pdu + 2 + 6, other, 6);
    ll[0] = 0x77;
    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10060000, record_send, &log) == 1);
}

static void test_follow_relay_retry(void)
{
    bh_follow_relay relay;
    struct relay_log log = { 0 };
    uint8_t pdu[2 + 34];
    uint8_t *ll = pdu + 14;
    bh_packet pkt;

    bh_follow_relay_init(&relay, 0, NULL);
    bh_follow_relay_register(&relay, 0);
    bh_follow_relay_register(&relay, 1);
    bh_follow_relay_register(&relay, 2);
    bh_follow_relay_observe(&relay, 0, 1000, 10000000);
    bh_follow_relay_observe(&relay, 1, 1500, 10010000);      /* board 2 has no offset yet */

    memset(pdu, 0, sizeof(pdu));
    pdu[0] = 0x05;
    pdu[1] = 34;
    ll[0] = 0x9A; ll[1] = 0xBC; ll[2] = 0xDE; ll[3] = 0xF0;
    ll[7] = 1; ll[10] = 24; ll[14] = 200;
    memset(ll + 16, 0xFF, 4); ll[20] = 0x1F; ll[21] = 0x05;
    memset(&pkt, 0, sizeof(pkt));
    pkt.access_addr = BH_ADV_ACCESS_ADDR;
    pkt.crc_ok = true;
    pkt.pdu = pdu;
    pkt.pdu_len = sizeof(pdu);
    pkt.channel = 37;
    pkt.ts_us = 5000;

    /* Only board 1 reachable at first. */
    CHECK(bh_follow_relay_maybe_relay(&relay, 0, &pkt, 10020000, record_send, &log) == 1);
    CHECK(log.count == 1 && log.board[0] == 1);
    CHECK(relay.stats.skipped_no_offset == 1);

    /* Too early for a retry; nothing sent. */
    CHECK(bh_follow_relay_retry(&relay, 10500000, record_send, &log) == 0);

    /* Board 2's sync offset arrives; board 1 has produced data for the connection. */
    bh_follow_relay_observe(&relay, 2, 800, 10020000);
    bh_packet data;
    memset(&data, 0, sizeof(data));
    data.access_addr = 0xF0DEBC9A;
    data.pdu = pdu;
    data.pdu_len = 2;
    bh_follow_relay_note_packet(&relay, 1, &data);

    /* After the retry interval only board 2 is sent to. */
    CHECK(bh_follow_relay_retry(&relay, 11100000, record_send, &log) == 1);
    CHECK(log.count == 2 && log.board[1] == 2);
    CHECK(relay.stats.retried == 1);

    /* Board 2 picks it up: no further retries. */
    bh_follow_relay_note_packet(&relay, 2, &data);
    CHECK(bh_follow_relay_retry(&relay, 12200000, record_send, &log) == 0);

    /* A board that stays silent is retried, but only a few times and only within the TTL. */
    bh_follow_relay relay2;
    struct relay_log log2 = { 0 };
    bh_follow_relay_init(&relay2, 0, NULL);
    bh_follow_relay_register(&relay2, 0);
    bh_follow_relay_register(&relay2, 1);
    bh_follow_relay_observe(&relay2, 0, 1000, 10000000);
    bh_follow_relay_observe(&relay2, 1, 1500, 10010000);
    CHECK(bh_follow_relay_maybe_relay(&relay2, 0, &pkt, 10020000, record_send, &log2) == 1);
    int extra = 0;
    for (int64_t t = 10020000; t < 10020000 + 8000000; t += 500000) {
        extra += bh_follow_relay_retry(&relay2, t, record_send, &log2);
    }
    CHECK(extra == BH_RELAY_MAX_TRIES - 1);
}

/* BT Core Spec Vol 6, Part C: encryption sample data. */
static const char *SPEC_LTK_MSO = "4C68384139F574D836BCF34E9DFB01BF";

static void spec_ltk_le(uint8_t out[16])
{
    uint8_t mso[16];
    CHECK(bh_parse_hex(SPEC_LTK_MSO, mso, 16));
    for (int i = 0; i < 16; i++) {
        out[i] = mso[15 - i];
    }
}

static void feed(bh_decryptor *d, uint32_t aa, const char *hex, bool *decrypted, uint8_t *dir,
                 uint8_t *out, size_t *out_len)
{
    uint8_t pdu[64];
    uint8_t buf[64];
    size_t n = strlen(hex) / 2;
    bh_packet pkt;

    CHECK(bh_parse_hex(hex, pdu, n));
    memset(&pkt, 0, sizeof(pkt));
    pkt.access_addr = aa;
    pkt.crc_ok = true;
    pkt.pdu = pdu;
    pkt.pdu_len = (uint8_t)n;
    *decrypted = bh_decryptor_process(d, &pkt, buf, sizeof(buf), dir);
    if (out) {
        memcpy(out, pkt.pdu, pkt.pdu_len);
        *out_len = pkt.pdu_len;
    }
}

static void test_ccm_spec_vectors(void)
{
    uint8_t sk[16], nonce[13], pt[32], ct[32], mic[4];

    CHECK(bh_parse_hex("99AD1B5226A37E3E058E3B8E27C2C666", sk, 16));
    /* nonce = counter(5, LSB first, bit 7 of byte 4 = direction) || IVm || IVs */
    memset(nonce, 0, sizeof(nonce));
    nonce[4] = 0x80;                                         /* central -> peripheral */
    CHECK(bh_parse_hex("24ABDCBABEBAAFDE", nonce + 5, 8));
    pt[0] = 0x06;                                            /* LL_START_ENC_RSP */
    bh_ccm_encrypt(sk, nonce, 0x0F & 0xE3, pt, 1, ct, mic);
    CHECK(ct[0] == 0x9F);
    CHECK(mic[0] == 0xCD && mic[1] == 0xA7 && mic[2] == 0xF4 && mic[3] == 0x48);
    CHECK(bh_ccm_decrypt(sk, nonce, 0x0F & 0xE3, ct, 1, mic, pt) && pt[0] == 0x06);
    mic[3] ^= 1;
    CHECK(!bh_ccm_decrypt(sk, nonce, 0x0F & 0xE3, ct, 1, mic, pt));

    nonce[4] = 0x00;                                         /* peripheral -> central */
    pt[0] = 0x06;
    bh_ccm_encrypt(sk, nonce, 0x07 & 0xE3, pt, 1, ct, mic);
    CHECK(ct[0] == 0xA3);
    CHECK(mic[0] == 0x4C && mic[1] == 0x13 && mic[2] == 0xA4 && mic[3] == 0x15);
}

static void test_decryptor_session(void)
{
    bh_decryptor d;
    uint8_t ltk[16], wrong[16], out[64], dir;
    size_t out_len;
    bool ok;
    const uint32_t aa = 0x12345678;

    spec_ltk_le(ltk);
    memset(wrong, 0x55, sizeof(wrong));
    bh_decryptor_init(&d);
    CHECK(bh_decryptor_add_ltk(&d, wrong));                 /* a key for some other device */
    CHECK(bh_decryptor_add_ltk(&d, ltk));

    /* LL_ENC_REQ: Rand ABCDEF1234567890 EDIV 2474 SKDm ACBDCEDFE0F10213 IVm BADCAB24 (all LE on air) */
    feed(&d, aa, "0317" "03" "9078563412EFCDAB" "7424" "1302F1E0DFCEBDAC" "24ABDCBA", &ok, &dir, NULL, NULL);
    CHECK(!ok);
    /* LL_ENC_RSP: SKDs 0213243546576879 IVs DEAFBABE */
    feed(&d, aa, "070D" "04" "7968574635241302" "BEBAAFDE", &ok, &dir, NULL, NULL);
    CHECK(!ok);
    CHECK(d.stats.sessions == 1);
    /* LL_START_ENC_REQ (plain, from the peripheral) */
    feed(&d, aa, "0701" "05", &ok, &dir, NULL, NULL);
    CHECK(!ok);

    /* Spec: central LL_START_ENC_RSP, counter 0 */
    feed(&d, aa, "0F059FCDA7F448", &ok, &dir, out, &out_len);
    CHECK(ok);
    CHECK(dir == BH_DIR_CENTRAL_PERIPHERAL);
    CHECK(out_len == 3 && out[0] == 0x0F && out[1] == 0x01 && out[2] == 0x06);
    /* Spec: peripheral LL_START_ENC_RSP, counter 0 */
    feed(&d, aa, "0705A34C13A415", &ok, &dir, out, &out_len);
    CHECK(ok);
    CHECK(dir == BH_DIR_PERIPHERAL_CENTRAL);
    CHECK(out[2] == 0x06);

    /* Data, counter 1 both ways (generated with the spec SK). */
    const char *plain = "1700636465666768696A6B6C6D6E6F70713132333435363738393031";
    uint8_t expect[28];
    CHECK(bh_parse_hex(plain, expect, 28));
    feed(&d, aa, "0E207A70D66415226DF26B17839A060405596BD6564F796B5B9CE6FF32710014E1E9", &ok, &dir, out, &out_len);
    CHECK(ok && dir == BH_DIR_CENTRAL_PERIPHERAL && out_len == 30 && out[1] == 28 && memcmp(out + 2, expect, 28) == 0);
    feed(&d, aa, "0620F388D5B5EDC69D9931E38C4668F76DB09CF542B72B7476D74DB5BEBE4864B552", &ok, &dir, out, &out_len);
    CHECK(ok && dir == BH_DIR_PERIPHERAL_CENTRAL && memcmp(out + 2, expect, 28) == 0);

    /* Missed packets: central jumps to counter 7; a peripheral retransmission reuses counter 2 twice. */
    feed(&d, aa, "0A20072F457BD06A21A05FE77B4379AF9B7AC0B44A71875ED750442C4A285C4B68BA", &ok, &dir, out, &out_len);
    CHECK(ok && dir == BH_DIR_CENTRAL_PERIPHERAL);
    feed(&d, aa, "1A20875D95DCE69867D8405F9A7D43C855202B4658ADC65342FA45A3E51D46D1EEE1", &ok, &dir, out, &out_len);
    CHECK(ok && dir == BH_DIR_PERIPHERAL_CENTRAL);
    feed(&d, aa, "1A20875D95DCE69867D8405F9A7D43C855202B4658ADC65342FA45A3E51D46D1EEE1", &ok, &dir, out, &out_len);
    CHECK(ok && dir == BH_DIR_PERIPHERAL_CENTRAL);
    CHECK(d.stats.decrypted == 7);

    /* The decrypted channel-map update is what the device must be told about. */
    {
        bh_packet hp;
        uint8_t args[64];
        uint8_t map_pdu[] = { 0x03, 0x08, 0x01, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x3a, 0x02 };
        memset(&hp, 0, sizeof(hp));
        hp.access_addr = aa;
        hp.pdu = map_pdu;
        hp.pdu_len = sizeof(map_pdu);
        CHECK(bh_ll_ctrl_hint_wanted(&hp));
        CHECK(bh_ll_ctrl_hint_args(&hp, args, sizeof(args)) == 4 + sizeof(map_pdu));
        CHECK(args[0] == 0x78 && args[3] == 0x12 && args[4] == 0x03 && args[6] == 0x01);
        CHECK(bh_ll_ctrl_hint_args(&hp, args, 8) == 0);
        map_pdu[2] = 0x14;                                       /* LL_LENGTH_REQ: not needed */
        CHECK(!bh_ll_ctrl_hint_wanted(&hp));
        map_pdu[0] = 0x02; map_pdu[2] = 0x01;                     /* not a control PDU */
        CHECK(!bh_ll_ctrl_hint_wanted(&hp));
    }

    /* Empty PDUs and garbage pass through untouched. */
    feed(&d, aa, "0100", &ok, &dir, out, &out_len);
    CHECK(!ok && out_len == 2);
    feed(&d, aa, "0E20000000000000000000000000000000000000000000000000000000000000000000", &ok, &dir, out, &out_len);
    CHECK(!ok && out_len >= 33);
    CHECK(d.stats.failed == 1);

    /* A connection with no ENC_REQ/RSP seen stays untouched. */
    feed(&d, 0x55AA55AA, "0F059FCDA7F448", &ok, &dir, out, &out_len);
    CHECK(!ok && out_len == 7);
}

static void test_sync_clock_extra_edge(void)
{
    bh_sync_clock c;
    uint32_t off;

    bh_sync_clock_init(&c, 0, BH_SYNC_PAIR_WINDOW_US);
    /* Edge 1 at host 10.000 s: ref tick 1000000, board tick 5000000 -> offset 4000000 */
    bh_sync_clock_observe(&c, 0, 1000000, 10000000);
    bh_sync_clock_observe(&c, 1, 5000000, 10001000);
    CHECK(bh_sync_clock_offset(&c, 1, &off) && off == 4000000);
    /* The reference emits an extra edge 0.48 s later (a hit). Both reference
     * edges are inside the 0.5 s window: the one heard closest must win. */
    bh_sync_clock_observe(&c, 0, 1480000, 10480000);
    bh_sync_clock_observe(&c, 1, 5480000, 10481000);
    CHECK(bh_sync_clock_offset(&c, 1, &off) && off == 4000000);
    /* A single stray pairing 0.48 s off does not move the offset... */
    bh_sync_clock_observe(&c, 0, 2000000, 11000000);
    bh_sync_clock_observe(&c, 1, 6480000, 11001000);
    CHECK(bh_sync_clock_offset(&c, 1, &off) && off == 4000000);
    /* ...but a board that really restarted (new offset seen twice) is adopted. */
    bh_sync_clock_observe(&c, 0, 3000000, 12000000);
    bh_sync_clock_observe(&c, 1, 100000, 12001000);
    bh_sync_clock_observe(&c, 0, 4000000, 13000000);
    bh_sync_clock_observe(&c, 1, 1100000, 13001000);
    CHECK(bh_sync_clock_offset(&c, 1, &off) && off == (uint32_t)(1100000 - 4000000));
}

int main(void)
{
    test_sync_clock_extra_edge();
    test_ccm_spec_vectors();
    test_decryptor_session();
    test_aes_and_rpa();
    test_follow_relay_irk();
    test_follow_relay_retry();
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
    test_sync_clock();
    test_sync_clock_pairing();
    test_aggregate();
    test_hold_until_synced();
    test_reorder_window();
    test_guard_channel();
    test_follow_relay();
    test_ts_mapper_mono();
    test_adv_parse();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("libblehound: all tests passed\n");
    return EXIT_SUCCESS;
}
