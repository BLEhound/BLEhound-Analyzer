/* cobs.c
 * COBS framing and the serial stream deframer. Mirrors the firmware's cobs.c.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "blehound/blehound.h"

bool bh_cobs_decode(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        uint8_t code = in[i++];
        if (code == 0) {
            return false;           /* 0x00 never appears inside a frame */
        }
        size_t run = (size_t)code - 1;
        if (i + run > in_len || o + run > out_cap) {
            return false;           /* truncated, or no room */
        }
        memcpy(out + o, in + i, run);
        o += run;
        i += run;
        if (code != 0xFF && i < in_len) {
            if (o >= out_cap) {
                return false;
            }
            out[o++] = 0;
        }
    }
    *out_len = o;
    return true;
}

size_t bh_cobs_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap)
{
    size_t code_pos = 0;
    size_t o = 1;
    uint8_t code = 1;

    if (out_cap < 2) {
        return 0;
    }
    for (size_t i = 0; i < in_len; i++) {
        if (in[i] == 0) {
            out[code_pos] = code;
            code_pos = o++;
            code = 1;
        } else {
            if (o >= out_cap) {
                return 0;
            }
            out[o++] = in[i];
            if (++code == 0xFF) {
                out[code_pos] = code;
                code_pos = o++;
                code = 1;
            }
        }
        if (o >= out_cap) {
            return 0;
        }
    }
    out[code_pos] = code;
    if (o >= out_cap) {
        return 0;
    }
    out[o++] = 0;                   /* frame delimiter */
    return o;
}

void bh_deframer_init(bh_deframer *d)
{
    memset(d, 0, sizeof(*d));
}

static void deframer_flush(bh_deframer *d, bh_frame_cb cb, void *ctx)
{
    uint8_t decoded[BH_MAX_FRAME_LEN];
    size_t decoded_len;

    if (d->overflow) {
        d->bad_frames++;
    } else if (d->len > 0) {
        if (bh_cobs_decode(d->buf, d->len, decoded, sizeof(decoded), &decoded_len)) {
            cb(ctx, decoded, decoded_len);
        } else {
            d->bad_frames++;
        }
    }
    d->len = 0;
    d->overflow = false;
}

void bh_deframer_feed(bh_deframer *d, const uint8_t *data, size_t len,
                      bh_frame_cb cb, void *ctx)
{
    for (size_t i = 0; i < len; i++) {
        if (data[i] == 0) {
            deframer_flush(d, cb, ctx);
        } else if (d->len < sizeof(d->buf)) {
            d->buf[d->len++] = data[i];
        } else {
            d->overflow = true;
        }
    }
}
