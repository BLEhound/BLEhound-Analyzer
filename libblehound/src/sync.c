/* sync.c
 * Inter-board clock alignment from SYNC edges, guard channels and the
 * follow relay.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include "blehound/blehound.h"

#define UNIT_US             1250
#define TX_WIN_DELAY_US     1250
#define AIR_US_PER_BYTE     8

int32_t bh_sdiff32(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b);
}

bool bh_guard_channel_for_board(uint8_t board_id, uint8_t *channel)
{
    if (board_id > 2) {
        return false;
    }
    *channel = (uint8_t)(37 + board_id);
    return true;
}

/* ----------------------------------------------------------- sync clock */

void bh_sync_clock_init(bh_sync_clock *c, uint8_t ref_board, int64_t pair_window_us)
{
    memset(c, 0, sizeof(*c));
    c->ref_board = ref_board;
    c->pair_window_us = pair_window_us;
}

static bool within_window(const bh_sync_clock *c, const bh_sync_edge *a, const bh_sync_edge *b)
{
    if (a->host_us == BH_NO_HOST_TIME || b->host_us == BH_NO_HOST_TIME) {
        return true;
    }
    int64_t d = a->host_us - b->host_us;
    return (d < 0 ? -d : d) <= c->pair_window_us;
}

/* Newest edge of the board against newest edge of the reference that was
 * heard at about the same time: those are the same physical edge. */
static void pair_board(bh_sync_clock *c, uint8_t board)
{
    const bh_sync_edge *bh = c->hist[board];
    const bh_sync_edge *rh = c->hist[c->ref_board];

    for (int i = c->hist_len[board] - 1; i >= 0; i--) {
        for (int j = c->hist_len[c->ref_board] - 1; j >= 0; j--) {
            if (within_window(c, &bh[i], &rh[j])) {
                c->offset[board] = bh[i].tick - rh[j].tick;
                c->has_offset[board] = true;
                return;
            }
        }
    }
}

void bh_sync_clock_observe(bh_sync_clock *c, uint8_t board_id, uint32_t tick, int64_t host_us)
{
    bh_sync_edge *h = c->hist[board_id];
    uint8_t *len = &c->hist_len[board_id];

    if (tick == 0) {
        return;
    }
    if (*len > 0 && h[*len - 1].tick == tick) {
        return;                 /* every frame repeats the latest edge */
    }
    if (*len == BH_SYNC_HIST) {
        memmove(h, h + 1, (BH_SYNC_HIST - 1) * sizeof(*h));
        (*len)--;
    }
    h[*len].tick = tick;
    h[*len].host_us = host_us;
    (*len)++;

    if (board_id == c->ref_board) {
        for (int b = 0; b < BH_MAX_BOARDS; b++) {
            if (b != c->ref_board && c->hist_len[b] > 0) {
                pair_board(c, (uint8_t)b);
            }
        }
    } else {
        pair_board(c, board_id);
    }
}

bool bh_sync_clock_offset(const bh_sync_clock *c, uint8_t board_id, uint32_t *offset)
{
    if (board_id == c->ref_board) {
        *offset = 0;
        return true;
    }
    if (!c->has_offset[board_id]) {
        return false;
    }
    *offset = c->offset[board_id];
    return true;
}

bool bh_sync_clock_to_ref(const bh_sync_clock *c, uint8_t board_id, uint32_t tick, uint32_t *ref_tick)
{
    uint32_t offset;

    if (!bh_sync_clock_offset(c, board_id, &offset)) {
        return false;
    }
    *ref_tick = tick - offset;
    return true;
}

/* --------------------------------------------------------- follow relay */

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | p[1] << 8);
}

bool bh_is_connect_ind(const bh_packet *pkt)
{
    return pkt->access_addr == BH_ADV_ACCESS_ADDR &&
           pkt->pdu_len >= 2 + 34 &&
           (pkt->pdu[0] & 0x0F) == 0x05 &&
           pkt->channel >= 37;
}

bool bh_parse_connect_ind(const uint8_t *pdu, size_t len, bh_connect_ind *ci)
{
    if (len < 2 + 34) {
        return false;
    }
    const uint8_t *ll = pdu + 2 + 12;   /* header, InitA, AdvA */

    ci->aa = (uint32_t)ll[0] | (uint32_t)ll[1] << 8 | (uint32_t)ll[2] << 16 | (uint32_t)ll[3] << 24;
    ci->crc_init = (uint32_t)ll[4] | (uint32_t)ll[5] << 8 | (uint32_t)ll[6] << 16;
    ci->win_size = ll[7];
    ci->win_offset = get_le16(ll + 8);
    ci->interval = get_le16(ll + 10);
    ci->latency = get_le16(ll + 12);
    ci->timeout = get_le16(ll + 14);
    memcpy(ci->chan_map, ll + 16, sizeof(ci->chan_map));
    ci->hop = ll[21] & 0x1F;
    ci->csa2 = (pdu[0] & 0x20) != 0;
    memcpy(ci->adva, pdu + 2 + 6, sizeof(ci->adva));
    return true;
}

void bh_follow_params(const bh_connect_ind *ci, uint32_t anchor0_us, uint8_t out[BH_FOLLOW_PARAMS_LEN])
{
    size_t o = 0;

    out[o++] = (uint8_t)ci->aa;
    out[o++] = (uint8_t)(ci->aa >> 8);
    out[o++] = (uint8_t)(ci->aa >> 16);
    out[o++] = (uint8_t)(ci->aa >> 24);
    out[o++] = (uint8_t)ci->crc_init;
    out[o++] = (uint8_t)(ci->crc_init >> 8);
    out[o++] = (uint8_t)(ci->crc_init >> 16);
    memcpy(out + o, ci->chan_map, sizeof(ci->chan_map));
    o += sizeof(ci->chan_map);
    out[o++] = ci->hop & 0x1F;
    out[o++] = ci->csa2 ? 1 : 0;
    out[o++] = (uint8_t)ci->interval;
    out[o++] = (uint8_t)(ci->interval >> 8);
    out[o++] = (uint8_t)ci->latency;
    out[o++] = (uint8_t)(ci->latency >> 8);
    out[o++] = (uint8_t)ci->timeout;
    out[o++] = (uint8_t)(ci->timeout >> 8);
    out[o++] = ci->win_size;
    out[o++] = (uint8_t)anchor0_us;
    out[o++] = (uint8_t)(anchor0_us >> 8);
    out[o++] = (uint8_t)(anchor0_us >> 16);
    out[o++] = (uint8_t)(anchor0_us >> 24);
}

void bh_follow_relay_init(bh_follow_relay *r, uint8_t ref_board, const uint8_t *target_le)
{
    memset(r, 0, sizeof(*r));
    bh_sync_clock_init(&r->clock, ref_board, BH_SYNC_PAIR_WINDOW_US);
    if (target_le) {
        r->has_target = true;
        memcpy(r->target, target_le, sizeof(r->target));
    }
}

void bh_follow_relay_register(bh_follow_relay *r, uint8_t board_id)
{
    r->registered[board_id] = true;
}

void bh_follow_relay_set_irk(bh_follow_relay *r, const uint8_t *irk_le)
{
    r->has_irk = irk_le != NULL;
    if (irk_le) {
        memcpy(r->irk, irk_le, sizeof(r->irk));
    }
}

/* The target itself, or one of its resolvable private addresses. */
static bool relay_target_matches(const bh_follow_relay *r, const uint8_t adva[6])
{
    if (!r->has_target && !r->has_irk) {
        return true;
    }
    if (r->has_target && memcmp(adva, r->target, sizeof(r->target)) == 0) {
        return true;
    }
    return r->has_irk && bh_rpa_matches(r->irk, adva);
}

void bh_follow_relay_observe(bh_follow_relay *r, uint8_t board_id, uint32_t sync_epoch, int64_t host_us)
{
    bh_sync_clock_observe(&r->clock, board_id, sync_epoch, host_us);
}

bool bh_follow_relay_anchor0(const bh_follow_relay *r, uint8_t from_board, uint32_t ts_us,
                             uint8_t payload_len, uint16_t win_offset, uint8_t to_board,
                             uint32_t *anchor0_us)
{
    uint32_t air = (2u + payload_len + 3u) * AIR_US_PER_BYTE;
    uint32_t anchor_from = ts_us + air + TX_WIN_DELAY_US + (uint32_t)win_offset * UNIT_US;
    uint32_t ref, off_to;

    if (!bh_sync_clock_to_ref(&r->clock, from_board, anchor_from, &ref) ||
            !bh_sync_clock_offset(&r->clock, to_board, &off_to)) {
        return false;
    }
    *anchor0_us = ref + off_to;
    return true;
}

void bh_follow_relay_set_trust(bh_follow_relay *r, bool trust)
{
    r->trust_source = trust;
}

/* Entry for a connection relayed recently, or a fresh one (oldest recycled). */
static int relay_entry(bh_follow_relay *r, uint32_t aa, int64_t host_us, bool *is_new)
{
    int n = (int)(sizeof(r->relayed) / sizeof(r->relayed[0]));
    int slot = 0;

    *is_new = false;
    for (int i = 0; i < n; i++) {
        if (r->relayed[i].used && r->relayed[i].aa == aa &&
                host_us - r->relayed[i].host_us < BH_RELAY_TTL_US) {
            return i;
        }
    }
    for (int i = 0; i < n; i++) {
        if (!r->relayed[i].used) {
            slot = i;
            break;
        }
        if (r->relayed[i].host_us < r->relayed[slot].host_us) {
            slot = i;
        }
    }
    memset(&r->relayed[slot], 0, sizeof(r->relayed[slot]));
    r->relayed[slot].used = true;
    r->relayed[slot].aa = aa;
    r->relayed[slot].host_us = host_us;
    *is_new = true;
    return slot;
}

/* Send FOLLOW for entry @p e to every board that still needs it. */
static int relay_send_pending(bh_follow_relay *r, int e, int64_t host_us, bh_relay_send_cb cb, void *ctx,
                              bool retry)
{
    uint8_t params[BH_FOLLOW_PARAMS_LEN];
    int sent = 0;

    for (int b = 0; b < BH_MAX_BOARDS; b++) {
        uint32_t anchor;

        if (!r->registered[b] || b == r->relayed[e].from_board || r->relayed[e].seen[b]) {
            continue;
        }
        if (!retry && r->relayed[e].delivered[b]) {
            continue;
        }
        if (!bh_follow_relay_anchor0(r, r->relayed[e].from_board, r->relayed[e].ts_us,
                                     r->relayed[e].payload_len, r->relayed[e].ci.win_offset,
                                     (uint8_t)b, &anchor)) {
            r->stats.skipped_no_offset++;
            continue;
        }
        bh_follow_params(&r->relayed[e].ci, anchor, params);
        if (cb(ctx, (uint8_t)b, params, sizeof(params))) {
            sent++;
            r->stats.sent_cmds++;
            if (retry) {
                r->stats.retried++;
            }
            r->relayed[e].delivered[b] = true;
        }
    }
    if (sent > 0) {
        r->relayed[e].last_try_us = host_us;
        r->relayed[e].tries++;
    }
    return sent;
}

int bh_follow_relay_maybe_relay(bh_follow_relay *r, uint8_t from_board, const bh_packet *pkt,
                                int64_t host_us, bh_relay_send_cb cb, void *ctx)
{
    bh_connect_ind ci;
    bool is_new;

    if (!bh_is_connect_ind(pkt) || !bh_parse_connect_ind(pkt->pdu, pkt->pdu_len, &ci)) {
        return 0;
    }
    /* The catching board applied its own target filter before letting the
     * CONNECT_IND through; only re-check here when told not to trust it. */
    if (!r->trust_source && !relay_target_matches(r, ci.adva)) {
        r->stats.skipped_target++;
        return 0;
    }
    int e = relay_entry(r, ci.aa, host_us, &is_new);

    if (!is_new) {
        r->stats.skipped_dup++;
        return 0;
    }
    r->relayed[e].from_board = from_board;
    r->relayed[e].ts_us = pkt->ts_us;
    r->relayed[e].payload_len = pkt->pdu[1];
    r->relayed[e].ci = ci;
    r->relayed[e].seen[from_board] = true;

    int sent = relay_send_pending(r, e, host_us, cb, ctx, false);

    if (sent > 0) {
        r->stats.relayed++;
    }
    return sent;
}

void bh_follow_relay_note_packet(bh_follow_relay *r, uint8_t board_id, const bh_packet *pkt)
{
    int n = (int)(sizeof(r->relayed) / sizeof(r->relayed[0]));

    if (pkt->access_addr == BH_ADV_ACCESS_ADDR || board_id >= BH_MAX_BOARDS) {
        return;
    }
    for (int i = 0; i < n; i++) {
        if (r->relayed[i].used && r->relayed[i].aa == pkt->access_addr) {
            r->relayed[i].seen[board_id] = true;
            return;
        }
    }
}

int bh_follow_relay_retry(bh_follow_relay *r, int64_t host_us, bh_relay_send_cb cb, void *ctx)
{
    int n = (int)(sizeof(r->relayed) / sizeof(r->relayed[0]));
    int sent = 0;

    for (int i = 0; i < n; i++) {
        if (!r->relayed[i].used || r->relayed[i].tries >= BH_RELAY_MAX_TRIES ||
                host_us - r->relayed[i].host_us >= BH_RELAY_TTL_US ||
                host_us - r->relayed[i].last_try_us < BH_RELAY_RETRY_US) {
            continue;
        }
        bool pending = false;

        for (int b = 0; b < BH_MAX_BOARDS; b++) {
            if (r->registered[b] && b != r->relayed[i].from_board && !r->relayed[i].seen[b]) {
                pending = true;
            }
        }
        if (pending) {
            sent += relay_send_pending(r, i, host_us, cb, ctx, true);
        }
    }
    return sent;
}
