/* cmd.c
 * Host command encoding, MAC parsing and pcap headers.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ctype.h>
#include <string.h>

#include "blehound/blehound.h"

#define BH_MAX_CMD_ARG_LEN  32

size_t bh_cmd_build(uint8_t cmd, const uint8_t *arg, size_t arg_len,
                    uint8_t *out, size_t out_cap)
{
    uint8_t payload[1 + BH_MAX_CMD_ARG_LEN];

    if (arg_len > BH_MAX_CMD_ARG_LEN) {
        return 0;
    }
    payload[0] = cmd;
    if (arg_len > 0) {
        memcpy(payload + 1, arg, arg_len);
    }
    return bh_cobs_encode(payload, 1 + arg_len, out, out_cap);
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool bh_parse_mac(const char *text, uint8_t mac_le[6])
{
    uint8_t be[6];
    const char *p = text;

    while (isspace((unsigned char)*p)) {
        p++;
    }
    for (int i = 0; i < 6; i++) {
        int hi = hex_value(p[0]);
        int lo = hi < 0 ? -1 : hex_value(p[1]);
        if (lo < 0) {
            return false;
        }
        be[i] = (uint8_t)(hi << 4 | lo);
        p += 2;
        if (i < 5) {
            if (*p != ':' && *p != '-') {
                return false;
            }
            p++;
        }
    }
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (*p != '\0') {
        return false;
    }
    /* Display order is most-significant first; the air order is little-endian. */
    for (int i = 0; i < 6; i++) {
        mac_le[i] = be[5 - i];
    }
    return true;
}

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    put_le16(p, (uint16_t)v);
    put_le16(p + 2, (uint16_t)(v >> 16));
}

void bh_pcap_global_header(uint8_t out[BH_PCAP_GLOBAL_HEADER_LEN])
{
    put_le32(out, 0xA1B2C3D4);      /* magic, µs resolution */
    put_le16(out + 4, 2);           /* version major */
    put_le16(out + 6, 4);           /* version minor */
    put_le32(out + 8, 0);           /* thiszone */
    put_le32(out + 12, 0);          /* sigfigs */
    put_le32(out + 16, 65535);      /* snaplen */
    put_le32(out + 20, BH_DLT_BTLE_LL_WITH_PHDR);
}

void bh_pcap_record_header(uint64_t ts_epoch_us, uint32_t len,
                           uint8_t out[BH_PCAP_RECORD_HEADER_LEN])
{
    put_le32(out, (uint32_t)(ts_epoch_us / 1000000));
    put_le32(out + 4, (uint32_t)(ts_epoch_us % 1000000));
    put_le32(out + 8, len);         /* incl_len */
    put_le32(out + 12, len);        /* orig_len */
}
