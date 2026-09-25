/* raw2pcap.c
 * Convert a raw dongle serial dump into a pcap file.
 *
 * Used to check libblehound against the Python extcap byte for byte:
 *   raw2pcap <dump.bin> <out.pcap> <host_epoch_us> [--include-crc-errors]
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
    bool include_crc_errors;
    unsigned long written;
};

static void on_frame(void *opaque, const uint8_t *frame, size_t len)
{
    struct ctx *c = opaque;
    bh_packet pkt;
    uint8_t rec[BH_MAX_RECORD_LEN];
    uint8_t hdr[BH_PCAP_RECORD_HEADER_LEN];

    if (!bh_parse_frame(frame, len, &pkt)) {
        return;
    }
    if (!pkt.crc_ok && !c->include_crc_errors) {
        return;
    }
    size_t n = bh_btle_rf_record(&pkt, rec, sizeof(rec));
    bh_pcap_record_header(bh_ts_mapper_map(&c->ts, pkt.ts_us), (uint32_t)n, hdr);
    fwrite(hdr, 1, sizeof(hdr), c->out);
    fwrite(rec, 1, n, c->out);
    c->written++;
}

int main(int argc, char **argv)
{
    struct ctx c;
    bh_deframer d;
    uint8_t g[BH_PCAP_GLOBAL_HEADER_LEN];
    uint8_t buf[4096];
    size_t n;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <dump.bin> <out.pcap> <host_epoch_us> [--include-crc-errors]\n", argv[0]);
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
    c.include_crc_errors = argc > 4 && strcmp(argv[4], "--include-crc-errors") == 0;

    bh_pcap_global_header(g);
    fwrite(g, 1, sizeof(g), c.out);
    bh_deframer_init(&d);
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        bh_deframer_feed(&d, buf, n, on_frame, &c);
    }
    fclose(in);
    fclose(c.out);
    fprintf(stderr, "%lu packets, %llu bad frames\n", c.written, (unsigned long long)d.bad_frames);
    return EXIT_SUCCESS;
}
