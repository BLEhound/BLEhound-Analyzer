/* agg.c
 * Multi-board aggregation: align time base -> reorder -> dedup -> emit.
 *
 * Mirrors host/tri_aggregator.py (Aggregator) so that both produce the
 * same stream for the same input.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include "blehound/blehound.h"

#define HALF32              0x80000000u
#define WRAP64              (1ull << 32)
#define POOL_MAX            65536       /* reorder buffer hard cap (records) */
#define PENDING_MAX         8192        /* per board, before degrading */

/* Reorder buffer entry: records live in a pool, the heap orders indices. */
typedef struct heap_item {
    uint64_t key64;
    uint64_t seq;               /* insertion order breaks ties, like a stable sort */
    uint32_t idx;
} heap_item;

/* Output-side dedup: last emitted tick per (AA, CRC, PDU). Entries older
 * than the horizon are dropped after every emitted batch, so the list stays
 * short (one reorder window of traffic) and a linear scan is enough. */
typedef struct emitted_entry {
    uint32_t access_addr;
    uint32_t crc;
    uint8_t  pdu_len;
    uint8_t  pdu[BH_MAX_PDU_LEN];
    uint64_t key64;
} emitted_entry;

struct bh_aggregator {
    bh_sync_clock clock;
    uint32_t dedup_us;
    uint32_t reorder_us;

    bh_agg_packet *pool;
    uint32_t pool_cap;
    uint32_t *free_stack;
    uint32_t free_len;

    heap_item *heap;
    uint32_t heap_len;
    uint32_t heap_cap;
    uint64_t seq;
    bool have_max;
    uint64_t max_key64;

    /* 32-bit aligned tick -> monotonic 64-bit */
    bool have_prev;
    uint32_t prev_v;
    uint64_t base;

    /* Boards whose offset is unknown: packets held back. */
    bh_agg_packet *pending[BH_MAX_BOARDS];
    uint32_t pending_len[BH_MAX_BOARDS];
    uint32_t pending_cap[BH_MAX_BOARDS];
    uint32_t pending_first[BH_MAX_BOARDS];

    emitted_entry *emitted;
    uint32_t emitted_len;
    uint32_t emitted_cap;
};

/* ------------------------------------------------------------- packets */

void bh_agg_packet_from(bh_agg_packet *dst, const bh_packet *src, int64_t host_us)
{
    memset(dst, 0, sizeof(*dst));
    dst->ts_us = src->ts_us;
    dst->channel = src->channel;
    dst->rssi = src->rssi;
    dst->phy = src->phy;
    dst->access_addr = src->access_addr;
    dst->crc = src->crc;
    dst->crc_ok = src->crc_ok;
    dst->board_id = src->board_id;
    dst->sync_epoch = src->sync_epoch;
    dst->host_us = host_us;
    dst->pdu_len = src->pdu_len;
    memcpy(dst->pdu, src->pdu, src->pdu_len);
}

void bh_agg_packet_view(const bh_agg_packet *src, bh_packet *view)
{
    memset(view, 0, sizeof(*view));
    view->ts_us = src->ts_us;
    view->channel = src->channel;
    view->rssi = src->rssi;
    view->phy = src->phy;
    view->access_addr = src->access_addr;
    view->crc = src->crc;
    view->crc_ok = src->crc_ok;
    view->board_id = src->board_id;
    view->sync_epoch = src->sync_epoch;
    view->pdu = src->pdu;
    view->pdu_len = src->pdu_len;
}

/* ------------------------------------------------------------ lifetime */

bh_aggregator *bh_aggregator_new(uint32_t dedup_window_us, uint32_t reorder_window_us, uint8_t ref_board)
{
    bh_aggregator *a = calloc(1, sizeof(*a));

    if (a == NULL) {
        return NULL;
    }
    bh_sync_clock_init(&a->clock, ref_board, BH_SYNC_PAIR_WINDOW_US);
    a->dedup_us = dedup_window_us;
    a->reorder_us = reorder_window_us;
    return a;
}

void bh_aggregator_free(bh_aggregator *a)
{
    if (a == NULL) {
        return;
    }
    for (int b = 0; b < BH_MAX_BOARDS; b++) {
        free(a->pending[b]);
    }
    free(a->pool);
    free(a->free_stack);
    free(a->heap);
    free(a->emitted);
    free(a);
}

const bh_sync_clock *bh_aggregator_clock(const bh_aggregator *a)
{
    return &a->clock;
}

/* ---------------------------------------------------------- pool/heap */

static bool pool_alloc(bh_aggregator *a, uint32_t *idx)
{
    if (a->free_len > 0) {
        *idx = a->free_stack[--a->free_len];
        return true;
    }
    uint32_t used = a->heap_len;    /* every pooled record is in the heap */
    if (used >= a->pool_cap) {
        uint32_t cap = a->pool_cap ? a->pool_cap * 2 : 256;
        if (cap > POOL_MAX) {
            return false;
        }
        bh_agg_packet *pool = realloc(a->pool, cap * sizeof(*pool));
        uint32_t *stack = realloc(a->free_stack, cap * sizeof(*stack));
        if (pool) a->pool = pool;
        if (stack) a->free_stack = stack;
        if (pool == NULL || stack == NULL) {
            return false;
        }
        a->pool_cap = cap;
    }
    *idx = used;
    return true;
}

static void pool_release(bh_aggregator *a, uint32_t idx)
{
    a->free_stack[a->free_len++] = idx;
}

static bool heap_less(const heap_item *x, const heap_item *y)
{
    return x->key64 < y->key64 || (x->key64 == y->key64 && x->seq < y->seq);
}

static bool heap_push(bh_aggregator *a, heap_item item)
{
    if (a->heap_len == a->heap_cap) {
        uint32_t cap = a->heap_cap ? a->heap_cap * 2 : 256;
        heap_item *heap = realloc(a->heap, cap * sizeof(*heap));
        if (heap == NULL) {
            return false;
        }
        a->heap = heap;
        a->heap_cap = cap;
    }
    uint32_t i = a->heap_len++;
    while (i > 0) {
        uint32_t parent = (i - 1) / 2;
        if (!heap_less(&item, &a->heap[parent])) {
            break;
        }
        a->heap[i] = a->heap[parent];
        i = parent;
    }
    a->heap[i] = item;
    return true;
}

static heap_item heap_pop(bh_aggregator *a)
{
    heap_item top = a->heap[0];
    heap_item last = a->heap[--a->heap_len];
    uint32_t i = 0;

    while (true) {
        uint32_t l = 2 * i + 1, r = l + 1, m = i;
        const heap_item *mi = &last;
        if (l < a->heap_len && heap_less(&a->heap[l], mi)) { m = l; mi = &a->heap[l]; }
        if (r < a->heap_len && heap_less(&a->heap[r], mi)) { m = r; }
        if (m == i) {
            break;
        }
        a->heap[i] = a->heap[m];
        i = m;
    }
    if (a->heap_len > 0) {
        a->heap[i] = last;
    }
    return top;
}

/* ------------------------------------------------------- dedup table */

static emitted_entry *find_emitted(bh_aggregator *a, const bh_agg_packet *p)
{
    for (uint32_t i = 0; i < a->emitted_len; i++) {
        emitted_entry *e = &a->emitted[i];
        if (e->access_addr == p->access_addr && e->crc == p->crc &&
                e->pdu_len == p->pdu_len && memcmp(e->pdu, p->pdu, p->pdu_len) == 0) {
            return e;
        }
    }
    return NULL;
}

/* Same air packet already emitted from another board within the window?
 * If not, this packet becomes the reference copy for its key. */
static bool is_duplicate(bh_aggregator *a, const bh_agg_packet *p)
{
    emitted_entry *e = find_emitted(a, p);

    if (e != NULL) {
        uint64_t d = p->key64 > e->key64 ? p->key64 - e->key64 : e->key64 - p->key64;
        if (d <= a->dedup_us) {
            return true;
        }
        e->key64 = p->key64;
        return false;
    }
    if (a->emitted_len == a->emitted_cap) {
        uint32_t cap = a->emitted_cap ? a->emitted_cap * 2 : 256;
        emitted_entry *grown = realloc(a->emitted, cap * sizeof(*grown));
        if (grown == NULL) {
            return false;
        }
        a->emitted = grown;
        a->emitted_cap = cap;
    }
    e = &a->emitted[a->emitted_len++];
    e->access_addr = p->access_addr;
    e->crc = p->crc;
    e->pdu_len = p->pdu_len;
    memcpy(e->pdu, p->pdu, p->pdu_len);
    e->key64 = p->key64;
    return false;
}

/* Forget keys far older than the newest record of the batch just emitted. */
static void prune_emitted(bh_aggregator *a, uint64_t newest)
{
    int64_t horizon = (int64_t)a->reorder_us + (int64_t)a->dedup_us * 8;

    for (uint32_t i = 0; i < a->emitted_len; ) {
        if ((int64_t)(newest - a->emitted[i].key64) > horizon) {
            a->emitted[i] = a->emitted[--a->emitted_len];
        } else {
            i++;
        }
    }
}

/* --------------------------------------------------------- ingest/emit */

/* Only a big drop (> 2^31) is a wrap; a small step back is a late packet. */
static uint64_t to64(bh_aggregator *a, uint32_t v)
{
    if (!a->have_prev) {
        a->have_prev = true;
        a->prev_v = v;
        return v;
    }
    if (v < a->prev_v && (a->prev_v - v) > HALF32) {
        a->base += WRAP64;
    }
    if (v > a->prev_v || (a->prev_v - v) > HALF32) {
        a->prev_v = v;
    }
    return a->base + v;
}

static void release(bh_aggregator *a, bool final, bh_agg_emit_cb cb, void *ctx)
{
    uint64_t cutoff = 0;
    bool any = false;
    uint64_t newest = 0;

    if (a->heap_len == 0) {
        return;
    }
    if (!final) {
        if (a->max_key64 < a->reorder_us) {
            return;
        }
        cutoff = a->max_key64 - a->reorder_us;
    }
    while (a->heap_len > 0 && (final || a->heap[0].key64 <= cutoff)) {
        heap_item item = heap_pop(a);
        bh_agg_packet *p = &a->pool[item.idx];

        any = true;
        newest = item.key64;
        if (!is_duplicate(a, p)) {
            cb(ctx, p);
        }
        pool_release(a, item.idx);
    }
    if (any) {
        prune_emitted(a, newest);
    }
}

static void ingest(bh_aggregator *a, const bh_agg_packet *pkt, uint32_t aligned, bh_agg_emit_cb cb, void *ctx)
{
    uint32_t idx;

    if (!pool_alloc(a, &idx)) {
        release(a, true, cb, ctx);      /* buffer full: emit what we have */
        if (!pool_alloc(a, &idx)) {
            return;
        }
    }
    bh_agg_packet *rec = &a->pool[idx];
    *rec = *pkt;
    rec->aligned = aligned;
    rec->key64 = to64(a, aligned);

    heap_item item = { rec->key64, a->seq++, idx };
    if (!heap_push(a, item)) {
        pool_release(a, idx);
        return;
    }
    if (!a->have_max || rec->key64 > a->max_key64) {
        a->have_max = true;
        a->max_key64 = rec->key64;
    }
    release(a, false, cb, ctx);
}

static bool pending_push(bh_aggregator *a, uint8_t b, const bh_agg_packet *pkt)
{
    if (a->pending_len[b] == a->pending_cap[b]) {
        uint32_t cap = a->pending_cap[b] ? a->pending_cap[b] * 2 : 64;
        bh_agg_packet *q = realloc(a->pending[b], cap * sizeof(*q));
        if (q == NULL) {
            return false;
        }
        a->pending[b] = q;
        a->pending_cap[b] = cap;
    }
    if (a->pending_len[b] == 0) {
        a->pending_first[b] = pkt->ts_us;
    }
    a->pending[b][a->pending_len[b]++] = *pkt;
    return true;
}

/* Feed held packets, aligned if possible, else by their own raw ticks. */
static void pending_drain(bh_aggregator *a, uint8_t b, bool aligned, bh_agg_emit_cb cb, void *ctx)
{
    uint32_t n = a->pending_len[b];

    a->pending_len[b] = 0;
    for (uint32_t i = 0; i < n; i++) {
        const bh_agg_packet *p = &a->pending[b][i];
        uint32_t tick = p->ts_us;
        if (aligned) {
            bh_sync_clock_to_ref(&a->clock, b, p->ts_us, &tick);
        }
        ingest(a, p, tick, cb, ctx);
    }
}

void bh_aggregator_add(bh_aggregator *a, const bh_agg_packet *pkt, bh_agg_emit_cb cb, void *ctx)
{
    uint8_t b = pkt->board_id;
    uint32_t aligned;

    bh_sync_clock_observe(&a->clock, b, pkt->sync_epoch, pkt->host_us);

    if (!bh_sync_clock_to_ref(&a->clock, b, pkt->ts_us, &aligned)) {
        if (!pending_push(a, b, pkt)) {
            return;
        }
        if (bh_sdiff32(pkt->ts_us, a->pending_first[b]) < (int32_t)BH_AGG_PENDING_TIMEOUT_US &&
                a->pending_len[b] < PENDING_MAX) {
            return;
        }
        /* Single board or SYNC line broken: stop waiting, use raw ticks. */
        pending_drain(a, b, false, cb, ctx);
        return;
    }

    pending_drain(a, b, true, cb, ctx);
    ingest(a, pkt, aligned, cb, ctx);
}

void bh_aggregator_flush(bh_aggregator *a, bh_agg_emit_cb cb, void *ctx)
{
    for (int b = 0; b < BH_MAX_BOARDS; b++) {
        if (a->pending_len[b] > 0) {
            uint32_t off;
            pending_drain(a, (uint8_t)b, bh_sync_clock_offset(&a->clock, (uint8_t)b, &off), cb, ctx);
        }
    }
    release(a, true, cb, ctx);
}
