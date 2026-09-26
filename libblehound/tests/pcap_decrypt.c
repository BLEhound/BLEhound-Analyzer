/* pcap_decrypt.c
 * Decrypt a LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR capture offline with one or
 * more LTKs: pcap_decrypt in.pcap out.pcap LTK_HEX [LTK_HEX...]
 * LTKs are given in air / SMP order (LSO first), as a device log prints them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blehound/blehound.h"

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s in.pcap out.pcap LTK_HEX [LTK_HEX...]\n", argv[0]);
        return 2;
    }
    bh_decryptor d;
    bh_decryptor_init(&d);
    for (int i = 3; i < argc; i++) {
        uint8_t ltk[16];
        if (!bh_parse_hex(argv[i], ltk, 16) || !bh_decryptor_add_ltk(&d, ltk)) {
            fprintf(stderr, "bad LTK: %s\n", argv[i]);
            return 2;
        }
    }
    FILE *in = fopen(argv[1], "rb");
    FILE *out = fopen(argv[2], "wb");
    if (!in || !out) {
        perror("open");
        return 1;
    }
    uint8_t gh[24];
    if (fread(gh, 1, 24, in) != 24 || rd32(gh) != 0xa1b2c3d4 || rd32(gh + 20) != 256) {
        fprintf(stderr, "not a little-endian pcap with linktype 256\n");
        return 1;
    }
    fwrite(gh, 1, 24, out);

    uint8_t rh[16], body[2048], rec[2048], plain[BH_MAX_PDU_LEN + 2];
    unsigned frames = 0;
    while (fread(rh, 1, 16, in) == 16) {
        uint32_t caplen = rd32(rh + 8);
        if (caplen > sizeof(body) || fread(body, 1, caplen, in) != caplen) {
            break;
        }
        frames++;
        /* 10-byte pseudo header, AA, [coding], PDU, CRC(3) */
        uint16_t flags = (uint16_t)(body[8] | body[9] << 8);
        bool coded = (flags >> 14) == 2;             /* BH_PHY_CODED_S8 == 2 */
        size_t off = 10 + 4 + (coded ? 1 : 0);
        if (caplen < off + 2 + 3) {
            fwrite(rh, 1, 16, out); fwrite(body, 1, caplen, out);
            continue;
        }
        bh_packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.access_addr = rd32(body + 10);
        pkt.crc_ok = (flags & 0x0800) != 0;
        pkt.phy = (uint8_t)(flags >> 14);
        if (coded) pkt.phy = body[14] == 1 ? BH_PHY_CODED_S2 : BH_PHY_CODED_S8;
        pkt.pdu = body + off;
        pkt.pdu_len = (uint8_t)(caplen - off - 3);
        pkt.crc = (uint32_t)body[caplen - 3] | (uint32_t)body[caplen - 2] << 8 | (uint32_t)body[caplen - 1] << 16;
        pkt.channel = 0;
        pkt.rssi = (int8_t)body[1];

        uint8_t direction;
        uint16_t extra = 0;
        if (bh_decryptor_process(&d, &pkt, plain, sizeof(plain), &direction)) {
            extra = bh_rf_flags_for_decrypted(direction);
        }
        /* rebuild: keep the original pseudo header bytes 0..7, refresh flags */
        size_t n = 0;
        memcpy(rec, body, 8); n = 8;
        wr16(rec + n, (uint16_t)(flags | extra)); n += 2;
        wr32(rec + n, pkt.access_addr); n += 4;
        if (coded) rec[n++] = body[14];
        memcpy(rec + n, pkt.pdu, pkt.pdu_len); n += pkt.pdu_len;
        rec[n++] = (uint8_t)pkt.crc; rec[n++] = (uint8_t)(pkt.crc >> 8); rec[n++] = (uint8_t)(pkt.crc >> 16);
        wr32(rh + 8, (uint32_t)n);
        wr32(rh + 12, (uint32_t)n);
        fwrite(rh, 1, 16, out);
        fwrite(rec, 1, n, out);
    }
    fclose(in);
    fclose(out);
    fprintf(stderr, "%u frames; sessions %u, decrypted %u, failed %u\n",
            frames, d.stats.sessions, d.stats.decrypted, d.stats.failed);
    return 0;
}
