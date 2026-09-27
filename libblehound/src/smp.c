/* smp.c
 * SMP (mcumgr) over serial for USB DFU of the dongle: framing, a minimal CBOR
 * encoder/decoder and the handful of requests the firmware loader needs.
 *
 * Wire format (Zephyr subsys/mgmt/mcumgr/transport/src/serial_util.c):
 *   raw   = be16(len(payload) + 2) | SMP header | CBOR | be16(CRC-16/XMODEM over header+CBOR)
 *   lines = for each 93-byte chunk of raw: marker(2) + base64(chunk) + '\n'
 *           marker 0x06 0x09 on the first line, 0x04 0x14 on continuation lines
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "blehound/blehound.h"

#define SMP_MARK_PKT_1   0x06
#define SMP_MARK_PKT_2   0x09
#define SMP_MARK_FRAG_1  0x04
#define SMP_MARK_FRAG_2  0x14

/* ---- CRC-16/XMODEM -------------------------------------------------------- */

uint16_t bh_crc16_xmodem(uint16_t seed, const uint8_t *data, size_t len)
{
    uint16_t crc = seed;

    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* ---- base64 --------------------------------------------------------------- */

static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap)
{
    size_t need = (in_len + 2) / 3 * 4;
    size_t o = 0;

    if (out_cap < need) {
        return 0;
    }
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        size_t rem = in_len - i;

        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        out[o++] = (uint8_t)b64_chars[(v >> 18) & 63];
        out[o++] = (uint8_t)b64_chars[(v >> 12) & 63];
        out[o++] = rem > 1 ? (uint8_t)b64_chars[(v >> 6) & 63] : '=';
        out[o++] = rem > 2 ? (uint8_t)b64_chars[v & 63] : '=';
    }
    return o;
}

static int b64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/** @return decoded length, or -1 on malformed input / no room. */
static int b64_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap)
{
    size_t o = 0;

    if (in_len % 4 != 0) {
        return -1;
    }
    for (size_t i = 0; i < in_len; i += 4) {
        int v[4];
        int pad = 0;

        for (int k = 0; k < 4; k++) {
            uint8_t c = in[i + k];
            if (c == '=' && k >= 2 && i + 4 == in_len) {
                v[k] = 0;
                pad++;
            } else {
                v[k] = b64_value(c);
                if (v[k] < 0 || pad) {
                    return -1;
                }
            }
        }
        uint32_t bits = (uint32_t)v[0] << 18 | (uint32_t)v[1] << 12 | (uint32_t)v[2] << 6 | (uint32_t)v[3];
        size_t n = 3 - (size_t)pad;

        if (o + n > out_cap) {
            return -1;
        }
        out[o++] = (uint8_t)(bits >> 16);
        if (n > 1) out[o++] = (uint8_t)(bits >> 8);
        if (n > 2) out[o++] = (uint8_t)bits;
    }
    return (int)o;
}

/* ---- framing -------------------------------------------------------------- */

size_t bh_smp_encode(const bh_smp_hdr *hdr, const uint8_t *payload, size_t payload_len,
                     uint8_t *out, size_t out_cap)
{
    uint8_t raw[BH_SMP_MAX_PACKET + 4];
    size_t body_len = BH_SMP_HDR_LEN + payload_len;
    size_t raw_len;
    size_t o = 0;

    if (body_len > BH_SMP_MAX_PACKET || payload_len > 0xFFFF) {
        return 0;
    }
    raw[0] = (uint8_t)((body_len + 2) >> 8);
    raw[1] = (uint8_t)(body_len + 2);
    raw[2] = hdr->op;
    raw[3] = hdr->flags;
    raw[4] = (uint8_t)(payload_len >> 8);
    raw[5] = (uint8_t)payload_len;
    raw[6] = (uint8_t)(hdr->group >> 8);
    raw[7] = (uint8_t)hdr->group;
    raw[8] = hdr->seq;
    raw[9] = hdr->id;
    if (payload_len) {
        memcpy(raw + 10, payload, payload_len);
    }
    uint16_t crc = bh_crc16_xmodem(0, raw + 2, body_len);
    raw[10 + payload_len] = (uint8_t)(crc >> 8);
    raw[11 + payload_len] = (uint8_t)crc;
    raw_len = body_len + 4;

    for (size_t off = 0; off < raw_len; off += BH_SMP_FRAME_RAW) {
        size_t chunk = raw_len - off;
        if (chunk > BH_SMP_FRAME_RAW) {
            chunk = BH_SMP_FRAME_RAW;
        }
        if (o + 3 + (chunk + 2) / 3 * 4 > out_cap) {
            return 0;
        }
        out[o++] = off == 0 ? SMP_MARK_PKT_1 : SMP_MARK_FRAG_1;
        out[o++] = off == 0 ? SMP_MARK_PKT_2 : SMP_MARK_FRAG_2;
        o += b64_encode(raw + off, chunk, out + o, out_cap - o);
        out[o++] = '\n';
    }
    return o;
}

void bh_smp_deframer_init(bh_smp_deframer *d)
{
    memset(d, 0, sizeof(*d));
}

static void smp_deframer_line(bh_smp_deframer *d, bh_smp_packet_cb cb, void *ctx)
{
    const uint8_t *line = d->line;
    size_t len = d->line_len;
    bool first;

    if (len < 2) {
        return;
    }
    if (line[0] == SMP_MARK_PKT_1 && line[1] == SMP_MARK_PKT_2) {
        first = true;
        d->pkt_len = 0;
        d->expect_len = 0;
    } else if (line[0] == SMP_MARK_FRAG_1 && line[1] == SMP_MARK_FRAG_2) {
        first = false;
        if (d->expect_len == 0) {
            return;         /* continuation without a start: drop */
        }
    } else {
        return;             /* not an SMP line (e.g. a console message) */
    }

    int n = b64_decode(line + 2, len - 2, d->pkt + d->pkt_len, sizeof(d->pkt) - d->pkt_len);
    if (n < 0) {
        d->expect_len = 0;
        d->pkt_len = 0;
        return;
    }
    d->pkt_len += (size_t)n;
    if (first) {
        if (d->pkt_len < 2) {
            d->pkt_len = 0;
            return;
        }
        d->expect_len = (size_t)d->pkt[0] << 8 | d->pkt[1];
        if (d->expect_len < BH_SMP_HDR_LEN + 2 || d->expect_len > sizeof(d->pkt) - 2) {
            d->expect_len = 0;
            d->pkt_len = 0;
            return;
        }
    }
    if (d->pkt_len - 2 < d->expect_len) {
        return;             /* more fragments expected */
    }
    if (d->pkt_len - 2 > d->expect_len ||
            bh_crc16_xmodem(0, d->pkt + 2, d->expect_len) != 0) {
        d->expect_len = 0;
        d->pkt_len = 0;
        return;
    }
    const uint8_t *body = d->pkt + 2;
    bh_smp_hdr hdr;

    hdr.op = body[0];
    hdr.flags = body[1];
    hdr.len = (uint16_t)(body[2] << 8 | body[3]);
    hdr.group = (uint16_t)(body[4] << 8 | body[5]);
    hdr.seq = body[6];
    hdr.id = body[7];
    if ((size_t)hdr.len + BH_SMP_HDR_LEN + 2 == d->expect_len) {
        cb(ctx, &hdr, body + BH_SMP_HDR_LEN, hdr.len);
    }
    d->expect_len = 0;
    d->pkt_len = 0;
}

void bh_smp_deframer_feed(bh_smp_deframer *d, const uint8_t *data, size_t len,
                          bh_smp_packet_cb cb, void *ctx)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];

        if (c == '\n' || c == '\r') {
            if (d->line_len) {
                smp_deframer_line(d, cb, ctx);
            }
            d->line_len = 0;
        } else if (d->line_len < sizeof(d->line)) {
            d->line[d->line_len++] = c;
        } else {
            d->line_len = 0;        /* overlong line: drop it */
        }
    }
}

/* ---- minimal CBOR encoder ------------------------------------------------ */

typedef struct cbor_w {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool overflow;
} cbor_w;

static void cw_put(cbor_w *w, uint8_t b)
{
    if (w->len < w->cap) {
        w->buf[w->len++] = b;
    } else {
        w->overflow = true;
    }
}

static void cw_head(cbor_w *w, uint8_t major, uint64_t v)
{
    uint8_t m = (uint8_t)(major << 5);

    if (v < 24) {
        cw_put(w, (uint8_t)(m | v));
    } else if (v <= 0xFF) {
        cw_put(w, m | 24); cw_put(w, (uint8_t)v);
    } else if (v <= 0xFFFF) {
        cw_put(w, m | 25); cw_put(w, (uint8_t)(v >> 8)); cw_put(w, (uint8_t)v);
    } else {
        cw_put(w, m | 26);
        cw_put(w, (uint8_t)(v >> 24)); cw_put(w, (uint8_t)(v >> 16));
        cw_put(w, (uint8_t)(v >> 8)); cw_put(w, (uint8_t)v);
    }
}

static void cw_key(cbor_w *w, const char *key)
{
    size_t n = strlen(key);

    cw_head(w, 3, n);
    for (size_t i = 0; i < n; i++) {
        cw_put(w, (uint8_t)key[i]);
    }
}

static void cw_bstr(cbor_w *w, const uint8_t *data, size_t len)
{
    cw_head(w, 2, len);
    for (size_t i = 0; i < len; i++) {
        cw_put(w, data[i]);
    }
}

/* ---- minimal CBOR decoder ------------------------------------------------ */

typedef struct cbor_item {
    uint8_t major;
    uint64_t value;         /**< integer value, or length for strings/arrays/maps */
    bool indefinite;
    const uint8_t *data;    /**< string bytes */
    const uint8_t *next;    /**< first byte after this item (after string bytes) */
} cbor_item;

/** Parse the head of one item at @p p. @return false on truncation. */
static bool cr_head(const uint8_t *p, const uint8_t *end, cbor_item *it)
{
    if (p >= end) {
        return false;
    }
    it->major = (uint8_t)(p[0] >> 5);
    uint8_t ai = p[0] & 0x1F;
    const uint8_t *q = p + 1;
    it->indefinite = false;
    if (ai < 24) {
        it->value = ai;
    } else if (ai == 24) {
        if (q + 1 > end) return false;
        it->value = q[0]; q += 1;
    } else if (ai == 25) {
        if (q + 2 > end) return false;
        it->value = (uint64_t)q[0] << 8 | q[1]; q += 2;
    } else if (ai == 26) {
        if (q + 4 > end) return false;
        it->value = (uint64_t)q[0] << 24 | (uint64_t)q[1] << 16 | (uint64_t)q[2] << 8 | q[3]; q += 4;
    } else if (ai == 27) {
        if (q + 8 > end) return false;
        it->value = 0;
        for (int i = 0; i < 8; i++) it->value = it->value << 8 | q[i];
        q += 8;
    } else if (ai == 31) {
        it->indefinite = true;
        it->value = 0;
    } else {
        return false;
    }
    it->data = q;
    if ((it->major == 2 || it->major == 3) && !it->indefinite) {
        if (q + it->value > end) return false;
        q += it->value;
    }
    it->next = q;
    return true;
}

/** Skip one complete item (including nested content). @return pointer after it, NULL on error. */
static const uint8_t *cr_skip(const uint8_t *p, const uint8_t *end)
{
    cbor_item it;

    if (!cr_head(p, end, &it)) {
        return NULL;
    }
    if (it.major == 7 && (p[0] & 0x1F) == 31) {
        return it.next;                         /* "break" */
    }
    if (it.major == 2 || it.major == 3) {
        if (!it.indefinite) {
            return it.next;
        }
        p = it.next;
        while (p < end && p[0] != 0xFF) {
            p = cr_skip(p, end);
            if (!p) return NULL;
        }
        return p < end ? p + 1 : NULL;
    }
    if (it.major == 4 || it.major == 5) {
        uint64_t count = it.indefinite ? UINT64_MAX : it.value * (it.major == 5 ? 2 : 1);
        p = it.next;
        for (uint64_t i = 0; i < count; i++) {
            if (it.indefinite && p < end && p[0] == 0xFF) {
                return p + 1;
            }
            p = cr_skip(p, end);
            if (!p) return NULL;
        }
        return p;
    }
    if (it.major == 6) {
        return cr_skip(it.next, end);           /* tag: skip the tagged item */
    }
    return it.next;
}

/** Iterate a map: call @p fn for every key/value pair. @return false on malformed input. */
typedef void (*cbor_pair_fn)(void *ctx, const cbor_item *key, const cbor_item *val,
                             const uint8_t *val_start, const uint8_t *end);

static bool cr_map_foreach(const uint8_t *p, const uint8_t *end, cbor_pair_fn fn, void *ctx)
{
    cbor_item map;

    if (!cr_head(p, end, &map) || map.major != 5) {
        return false;
    }
    p = map.next;
    uint64_t count = map.indefinite ? UINT64_MAX : map.value;
    for (uint64_t i = 0; i < count; i++) {
        cbor_item key, val;

        if (map.indefinite && p < end && p[0] == 0xFF) {
            return true;
        }
        if (!cr_head(p, end, &key)) return false;
        const uint8_t *val_start = key.next;
        if (!cr_head(val_start, end, &val)) return false;
        const uint8_t *after = cr_skip(val_start, end);
        if (!after) return false;
        fn(ctx, &key, &val, val_start, end);
        p = after;
    }
    return true;
}

static bool key_is(const cbor_item *key, const char *name)
{
    size_t n = strlen(name);

    return key->major == 3 && !key->indefinite && key->value == n && memcmp(key->data, name, n) == 0;
}

static bool item_int(const cbor_item *it, int64_t *out)
{
    if (it->major == 0) { *out = (int64_t)it->value; return true; }
    if (it->major == 1) { *out = -1 - (int64_t)it->value; return true; }
    return false;
}

static bool item_bool(const cbor_item *it, bool *out)
{
    if (it->major == 7 && (it->value == 20 || it->value == 21)) {
        *out = it->value == 21;
        return true;
    }
    return false;
}

/* ---- requests ------------------------------------------------------------- */

static size_t smp_request(uint8_t op, uint16_t group, uint8_t id, uint8_t seq,
                          const uint8_t *cbor, size_t cbor_len, uint8_t *out, size_t out_cap)
{
    bh_smp_hdr hdr = { .op = op, .flags = 0, .len = (uint16_t)cbor_len, .group = group, .seq = seq, .id = id };

    return bh_smp_encode(&hdr, cbor, cbor_len, out, out_cap);
}

size_t bh_smp_req_params(uint8_t seq, uint8_t *out, size_t out_cap)
{
    const uint8_t empty_map[] = { 0xA0 };

    return smp_request(BH_SMP_OP_READ, BH_SMP_GROUP_OS, BH_SMP_ID_OS_PARAMS, seq,
                       empty_map, sizeof(empty_map), out, out_cap);
}

size_t bh_smp_req_image_state(uint8_t seq, uint8_t *out, size_t out_cap)
{
    const uint8_t empty_map[] = { 0xA0 };

    return smp_request(BH_SMP_OP_READ, BH_SMP_GROUP_IMAGE, BH_SMP_ID_IMG_STATE, seq,
                       empty_map, sizeof(empty_map), out, out_cap);
}

size_t bh_smp_req_reset(uint8_t seq, uint8_t *out, size_t out_cap)
{
    const uint8_t empty_map[] = { 0xA0 };

    return smp_request(BH_SMP_OP_WRITE, BH_SMP_GROUP_OS, BH_SMP_ID_OS_RESET, seq,
                       empty_map, sizeof(empty_map), out, out_cap);
}

/* map(4) + "image" 0 + "off" u32 + "len" u32 + "data" bstr(u16 length) = worst-case overhead */
#define SMP_UPLOAD_OVERHEAD  (1 + 6 + 1 + 4 + 5 + 4 + 5 + 5 + 3)

size_t bh_smp_upload_chunk_max(size_t buf_size)
{
    if (buf_size > BH_SMP_MAX_PACKET) {
        buf_size = BH_SMP_MAX_PACKET;
    }
    if (buf_size <= BH_SMP_HDR_LEN + SMP_UPLOAD_OVERHEAD + 16) {
        return 16;
    }
    return buf_size - BH_SMP_HDR_LEN - SMP_UPLOAD_OVERHEAD;
}

size_t bh_smp_req_image_upload(uint8_t seq, uint32_t off, uint32_t total_len,
                               const uint8_t *data, size_t data_len, uint8_t *out, size_t out_cap)
{
    uint8_t cbor[BH_SMP_MAX_PACKET];
    cbor_w w = { cbor, sizeof(cbor), 0, false };

    cw_head(&w, 5, off == 0 ? 4 : 2);
    if (off == 0) {
        cw_key(&w, "image"); cw_head(&w, 0, 0);
        cw_key(&w, "len");   cw_head(&w, 0, total_len);
    }
    cw_key(&w, "off");  cw_head(&w, 0, off);
    cw_key(&w, "data"); cw_bstr(&w, data, data_len);
    if (w.overflow) {
        return 0;
    }
    return smp_request(BH_SMP_OP_WRITE, BH_SMP_GROUP_IMAGE, BH_SMP_ID_IMG_UPLOAD, seq,
                       cbor, w.len, out, out_cap);
}

/* ---- responses ------------------------------------------------------------ */

typedef struct status_ctx {
    int32_t rc;
    uint32_t off;
    bool have_off;
} status_ctx;

static void status_pair(void *vctx, const cbor_item *key, const cbor_item *val,
                        const uint8_t *val_start, const uint8_t *end)
{
    status_ctx *c = vctx;
    int64_t v;

    (void)val_start; (void)end;
    if (key_is(key, "rc") && item_int(val, &v)) {
        c->rc = (int32_t)v;
    } else if (key_is(key, "off") && item_int(val, &v)) {
        c->off = (uint32_t)v;
        c->have_off = true;
    }
}

bool bh_smp_rsp_status(const uint8_t *cbor, size_t len, int32_t *rc, uint32_t *off)
{
    status_ctx c = { 0, 0, false };

    if (!cr_map_foreach(cbor, cbor + len, status_pair, &c)) {
        return false;
    }
    if (rc) *rc = c.rc;
    if (off && c.have_off) *off = c.off;
    return true;
}

typedef struct params_ctx { uint32_t buf_size, buf_count; } params_ctx;

static void params_pair(void *vctx, const cbor_item *key, const cbor_item *val,
                        const uint8_t *val_start, const uint8_t *end)
{
    params_ctx *c = vctx;
    int64_t v;

    (void)val_start; (void)end;
    if (key_is(key, "buf_size") && item_int(val, &v)) c->buf_size = (uint32_t)v;
    if (key_is(key, "buf_count") && item_int(val, &v)) c->buf_count = (uint32_t)v;
}

bool bh_smp_rsp_params(const uint8_t *cbor, size_t len, uint32_t *buf_size, uint32_t *buf_count)
{
    params_ctx c = { 0, 0 };

    if (!cr_map_foreach(cbor, cbor + len, params_pair, &c) || c.buf_size == 0) {
        return false;
    }
    if (buf_size) *buf_size = c.buf_size;
    if (buf_count) *buf_count = c.buf_count;
    return true;
}

static void image_pair(void *vctx, const cbor_item *key, const cbor_item *val,
                       const uint8_t *val_start, const uint8_t *end)
{
    bh_smp_image *img = vctx;
    int64_t v;
    bool b;

    (void)val_start; (void)end;
    if (key_is(key, "slot") && item_int(val, &v)) {
        img->slot = (uint8_t)v;
    } else if (key_is(key, "version") && val->major == 3 && !val->indefinite) {
        size_t n = val->value < sizeof(img->version) - 1 ? (size_t)val->value : sizeof(img->version) - 1;
        memcpy(img->version, val->data, n);
        img->version[n] = '\0';
    } else if (key_is(key, "hash") && val->major == 2 && !val->indefinite && val->value == 32) {
        memcpy(img->hash, val->data, 32);
        img->has_hash = true;
    } else if (key_is(key, "bootable") && item_bool(val, &b)) {
        img->bootable = b;
    } else if (key_is(key, "active") && item_bool(val, &b)) {
        img->active = b;
    } else if (key_is(key, "confirmed") && item_bool(val, &b)) {
        img->confirmed = b;
    } else if (key_is(key, "pending") && item_bool(val, &b)) {
        img->pending = b;
    }
}

typedef struct images_ctx {
    bh_smp_image *out;
    size_t max;
    int count;
    bool bad;
} images_ctx;

static void images_pair(void *vctx, const cbor_item *key, const cbor_item *val,
                        const uint8_t *val_start, const uint8_t *end)
{
    images_ctx *c = vctx;

    if (!key_is(key, "images") || val->major != 4) {
        return;
    }
    const uint8_t *p = val->next;
    uint64_t count = val->indefinite ? UINT64_MAX : val->value;

    for (uint64_t i = 0; i < count; i++) {
        if (val->indefinite && p < end && p[0] == 0xFF) {
            break;
        }
        if ((size_t)c->count < c->max) {
            bh_smp_image *img = &c->out[c->count];
            memset(img, 0, sizeof(*img));
            if (!cr_map_foreach(p, end, image_pair, img)) {
                c->bad = true;
                return;
            }
            c->count++;
        }
        p = cr_skip(p, end);
        if (!p) {
            c->bad = true;
            return;
        }
    }
    (void)val_start;
}

int bh_smp_rsp_images(const uint8_t *cbor, size_t len, bh_smp_image *out, size_t max_images)
{
    images_ctx c = { out, max_images, 0, false };

    if (!cr_map_foreach(cbor, cbor + len, images_pair, &c) || c.bad) {
        return -1;
    }
    return c.count;
}
