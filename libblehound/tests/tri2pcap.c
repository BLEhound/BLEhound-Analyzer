/* tri2pcap.c
 * Replay a multi-board frame log through the aggregator into a pcap file.
 *
 * Log format, one entry per frame in host arrival order:
 *   uint8 port_index, int64 host_us, uint32 len, then len bytes of the
 *   COBS-encoded frame (without the 0x00 delimiter). All little-endian.
 * Used to check libblehound against tri_aggregator.py byte for byte:
 *   tri2pcap <log.bin> <out.pcap> <host_epoch_us> [--include-crc-errors]
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blehound/blehound.h"

struct ctx {
    FILE *out;
    bh_ts_mapper ts;
    unsigned long written;
};

static void on_emit(void *opaque, const bh_agg_packet *pkt)
{
    struct ctx *c = opaque;
    bh_packet view;
    uint8_t rec[BH_MAX_RECORD_LEN];
    uint8_t hdr[BH_PCAP_RECORD_HEADER_LEN];

    bh_agg_packet_view(pkt, &view);
    size_t n = bh_btle_rf_record(&view, rec, sizeof(rec));
    bh_pcap_record_header((uint64_t)bh_ts_mapper_map_mono(&c->ts, pkt->key64), (uint32_t)n, hdr);
    fwrite(hdr, 1, sizeof(hdr), c->out);
    fwrite(rec, 1, n, c->out);
    c->written++;
}

static bool read_exact(FILE *f, void *buf, size_t n)
{
    return fread(buf, 1, n, f) == n;
}

int main(int argc, char **argv)
{
    struct ctx c;
    uint8_t g[BH_PCAP_GLOBAL_HEADER_LEN];
    uint8_t enc[BH_MAX_ENCODED_LEN];
    uint8_t raw[BH_MAX_FRAME_LEN];
    uint8_t head[13];
    bool include_crc_errors;
    unsigned long parsed = 0;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <log.bin> <out.pcap> <host_epoch_us> [--include-crc-errors]\n", argv[0]);
        return EXIT_FAILURE;
    }
    FILE *in = fopen(argv[1], "rb");
    memset(&c, 0, sizeof(c));
    c.out = fopen(argv[2], "wb");
    if (in == NULL || c.out == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    bh_ts_mapper_init(&c.ts, strtoull(argv[3], NULL, 10));
    include_crc_errors = argc > 4 && strcmp(argv[4], "--include-crc-errors") == 0;

    bh_pcap_global_header(g);
    fwrite(g, 1, sizeof(g), c.out);

    bh_aggregator *agg = bh_aggregator_new(BH_AGG_DEDUP_US, BH_AGG_REORDER_US, 0);
    while (read_exact(in, head, sizeof(head))) {
        int64_t host_us;
        uint32_t len;
        size_t raw_len;
        bh_packet pkt;
        bh_agg_packet rec;

        memcpy(&host_us, head + 1, sizeof(host_us));
        memcpy(&len, head + 9, sizeof(len));
        if (len > sizeof(enc) || !read_exact(in, enc, len)) {
            break;
        }
        if (!bh_cobs_decode(enc, len, raw, sizeof(raw), &raw_len) || !bh_parse_frame(raw, raw_len, &pkt)) {
            continue;
        }
        parsed++;
        if (!pkt.crc_ok && !include_crc_errors) {
            continue;
        }
        bh_agg_packet_from(&rec, &pkt, host_us);
        bh_aggregator_add(agg, &rec, on_emit, &c);
    }
    bh_aggregator_flush(agg, on_emit, &c);
    bh_aggregator_free(agg);
    fclose(in);
    fclose(c.out);
    fprintf(stderr, "%lu frames parsed, %lu packets written\n", parsed, c.written);
    return EXIT_SUCCESS;
}
