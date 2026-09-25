/* rpa.c
 * Resolvable private addresses: ah() from BT Core Spec Vol 3, Part H
 * §2.2.2, plus key text parsing.
 *
 * Byte order (verified on hardware): IRKs are handled in air / SMP
 * Identity Information order (LSO first), the form a device log prints as
 * "wire/LSO-first"; the AES key is that string reversed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "blehound/blehound.h"

#include <string.h>

bool bh_rpa_is_resolvable(const uint8_t addr_le[6])
{
    return (addr_le[5] & 0xC0) == 0x40;
}

bool bh_rpa_matches(const uint8_t irk_le[16], const uint8_t addr_le[6])
{
    uint8_t key[16];
    uint8_t blk[16] = { 0 };
    uint8_t out[16];

    if (!bh_rpa_is_resolvable(addr_le)) {
        return false;
    }
    for (int i = 0; i < 16; i++) {
        key[i] = irk_le[15 - i];
    }
    /* r' = padding (13 zero bytes) || prand, most significant octet first */
    blk[13] = addr_le[5];
    blk[14] = addr_le[4];
    blk[15] = addr_le[3];
    bh_aes128_encrypt(key, blk, out);
    return out[13] == addr_le[2] && out[14] == addr_le[1] && out[15] == addr_le[0];
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool bh_parse_hex(const char *text, uint8_t *out, size_t len)
{
    size_t n = 0;

    if (!text) {
        return false;
    }
    while (*text && n < len) {
        if (*text == ' ' || *text == ':' || *text == '-') {
            text++;
            continue;
        }
        int hi = hex_digit(text[0]);
        int lo = text[1] ? hex_digit(text[1]) : -1;

        if (hi < 0 || lo < 0) {
            return false;
        }
        out[n++] = (uint8_t)((hi << 4) | lo);
        text += 2;
    }
    while (*text == ' ') {
        text++;
    }
    return n == len && *text == '\0';
}
