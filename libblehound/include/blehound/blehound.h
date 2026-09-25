/* blehound.h
 * BLEhound sniffer dongle host protocol.
 *
 * The dongle is a USB CDC-ACM device (VID 0x1915, PID 0x520F). Once the
 * host asserts DTR it streams COBS-encoded frames separated by 0x00. Host
 * commands travel the other way with the same framing.
 *
 * This library is independent of Wireshark so that other hosts (Python
 * bindings, third-party tools) can share one implementation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BLEHOUND_H
#define BLEHOUND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BH_USB_VID                  0x1915
#define BH_USB_PID                  0x520F
#define BH_USB_PRODUCT              "BLEhound Sniffer"

/* pcap LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR */
#define BH_DLT_BTLE_LL_WITH_PHDR    256

/* Device -> host frame types. */
#define BH_FRAME_PACKET             0x01

/* Host -> device commands. */
#define BH_CMD_SET_CHANNEL          0x81    /* 1 byte: BLE channel index */
#define BH_CMD_SET_TARGET           0x84    /* 6 bytes: AdvA little-endian, all zero = no filter */
#define BH_CMD_SET_HOPPING          0x85    /* 1 byte: 1 = hop 37/38/39 */
#define BH_CMD_FOLLOW               0x86
#define BH_CMD_SET_SINGLE_TARGET    0x87    /* 1 byte: 1 = single-target (default), 0 = multi-target */

#define BH_MAX_PDU_LEN              255
#define BH_FRAME_HEADER_LEN         17
#define BH_TRI_EXT_LEN              5
#define BH_MAX_FRAME_LEN            (BH_FRAME_HEADER_LEN + BH_TRI_EXT_LEN + BH_MAX_PDU_LEN)
/* COBS adds one byte per 254 bytes plus one. */
#define BH_MAX_ENCODED_LEN          (BH_MAX_FRAME_LEN + BH_MAX_FRAME_LEN / 254 + 2)

/* phdr (10) + access address (4) + coding indicator (1) + PDU + CRC (3) */
#define BH_MAX_RECORD_LEN           (10 + 4 + 1 + BH_MAX_PDU_LEN + 3)

#define BH_PCAP_GLOBAL_HEADER_LEN   24
#define BH_PCAP_RECORD_HEADER_LEN   16

/* Firmware PHY codes. */
enum bh_phy {
    BH_PHY_1M       = 0,
    BH_PHY_2M       = 1,
    BH_PHY_CODED_S8 = 2,
    BH_PHY_CODED_S2 = 3,
};

/** One captured air packet, as reported by the dongle. */
typedef struct bh_packet {
    uint32_t       ts_us;        /**< firmware 1 MHz counter, wraps every ~71.6 min */
    uint8_t        channel;      /**< BLE channel index 0..39 */
    int8_t         rssi;         /**< dBm */
    uint8_t        phy;          /**< enum bh_phy */
    uint32_t       access_addr;
    uint32_t       crc;          /**< 24-bit CRC as received */
    bool           crc_ok;
    uint8_t        board_id;     /**< tri-board mode only, else 0 */
    uint32_t       sync_epoch;   /**< tri-board mode only, else 0 */
    const uint8_t *pdu;          /**< points into the decoded frame */
    uint8_t        pdu_len;
} bh_packet;

/* ------------------------------------------------------------------ COBS */

/**
 * Decode one COBS frame (without the 0x00 delimiter).
 * @return false on malformed input or if @p out_cap is too small.
 */
bool bh_cobs_decode(const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * COBS-encode @p in and append the 0x00 delimiter.
 * @return encoded length including the delimiter, or 0 if @p out_cap is too small.
 */
size_t bh_cobs_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap);

/* --------------------------------------------------------- stream deframer */

typedef void (*bh_frame_cb)(void *ctx, const uint8_t *frame, size_t len);

/** Splits the serial byte stream on 0x00 and COBS-decodes each frame. */
typedef struct bh_deframer {
    uint8_t  buf[BH_MAX_ENCODED_LEN];
    size_t   len;
    bool     overflow;      /**< current frame exceeded the buffer; drop it */
    uint64_t bad_frames;    /**< frames dropped as oversize or malformed */
} bh_deframer;

void bh_deframer_init(bh_deframer *d);

/** Feed raw serial bytes; @p cb is called once per decoded frame. */
void bh_deframer_feed(bh_deframer *d, const uint8_t *data, size_t len,
                      bh_frame_cb cb, void *ctx);

/* ---------------------------------------------------------------- frames */

/**
 * Parse one decoded device frame.
 * @return false if it is not a well-formed packet frame.
 */
bool bh_parse_frame(const uint8_t *raw, size_t len, bh_packet *pkt);

/** BLE channel index (0..39) to physical RF channel (2402 + 2n MHz). */
uint8_t bh_ble_to_rf_channel(uint8_t ble_channel);

/**
 * Build a LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR record body:
 * BTLE_RF pseudo-header + access address [+ coding indicator] + PDU + CRC.
 * @return record length, or 0 if @p out_cap is too small.
 */
size_t bh_btle_rf_record(const bh_packet *pkt, uint8_t *out, size_t out_cap);

/* ------------------------------------------------------------ timestamps */

/**
 * Maps the firmware's wrapping 32-bit microsecond counter onto host
 * wall-clock time: capture start instant + firmware-relative offset.
 */
typedef struct bh_ts_mapper {
    uint64_t host_epoch_us;
    uint32_t first_fw_us;
    uint32_t prev_fw_us;
    uint64_t wraps;
    bool     started;
    uint64_t first_mono_us;
    bool     mono_started;
} bh_ts_mapper;

void bh_ts_mapper_init(bh_ts_mapper *m, uint64_t host_epoch_us);

/** Packets must be mapped in arrival order; a backwards step is a wrap. */
uint64_t bh_ts_mapper_map(bh_ts_mapper *m, uint32_t fw_us);

/**
 * Aggregated path: @p mono_us is the aggregator's 64-bit key with wraps
 * already unrolled, so this is a plain linear mapping. A small backwards
 * step here is a late packet, not a wrap.
 */
int64_t bh_ts_mapper_map_mono(bh_ts_mapper *m, uint64_t mono_us);

/* -------------------------------------------------------------- commands */

/**
 * Build an encoded, delimited command ready to write to the serial port.
 * @return encoded length, or 0 if @p out_cap is too small.
 */
size_t bh_cmd_build(uint8_t cmd, const uint8_t *arg, size_t arg_len,
                    uint8_t *out, size_t out_cap);

/**
 * Parse "AA:BB:CC:DD:EE:FF" (or '-' separated) into air (little-endian) order.
 * @return false on malformed input.
 */
bool bh_parse_mac(const char *text, uint8_t mac_le[6]);

/* ------------------------------------------------------------------ pcap */

/** Classic pcap global header (µs resolution, LINKTYPE 256). Writes 24 bytes. */
void bh_pcap_global_header(uint8_t out[BH_PCAP_GLOBAL_HEADER_LEN]);

/** Classic pcap record header. Writes 16 bytes. */
void bh_pcap_record_header(uint64_t ts_epoch_us, uint32_t len,
                           uint8_t out[BH_PCAP_RECORD_HEADER_LEN]);

/* ------------------------------------------------------- advertising */

#define BH_ADV_NAME_MAX         32

enum bh_addr_kind {
    BH_ADDR_PUBLIC,
    BH_ADDR_RANDOM_STATIC,
    BH_ADDR_RANDOM_RESOLVABLE,
    BH_ADDR_RANDOM_NON_RESOLVABLE,
};

/** What an advertising-channel PDU tells about the advertiser. */
typedef struct bh_adv_info {
    uint8_t  pdu_type;          /**< PDU type nibble */
    bool     extended;          /**< ADV_EXT_IND / AUX_* (type 7) or AUX_CONNECT_RSP (8) */
    bool     connectable;
    bool     from_advertiser;   /**< sent by the advertiser (vs. SCAN_REQ/CONNECT_IND aimed at it) */
    uint8_t  adva[6];           /**< air (little-endian) order */
    bool     adva_random;
    bool     has_name;
    bool     name_complete;
    char     name[BH_ADV_NAME_MAX];
    bool     has_company;
    uint16_t company_id;        /**< from manufacturer-specific data */
} bh_adv_info;

/**
 * Parse an advertising-channel PDU and identify the advertiser it is about.
 * @return false if the packet is not on the advertising access address or
 *         carries no advertiser address (e.g. ADV_EXT_IND without AdvA).
 */
bool bh_adv_parse(const bh_packet *pkt, bh_adv_info *info);

enum bh_addr_kind bh_addr_kind(const uint8_t adva[6], bool random_addr);

/** "AA:BB:CC:DD:EE:FF" (display order) from an air-order address; @p out holds 18 bytes. */
void bh_format_mac(const uint8_t mac_le[6], char out[18]);

/* ------------------------------------------------- multi-board aggregation */

/*
 * Three dongles guard advertising channels 37/38/39 (board_id 0/1/2). Their
 * free-running 32-bit µs counters are not synchronised: board 0 raises a
 * SYNC edge about once a second, every board captures that edge on its own
 * counter and reports the most recent one as sync_epoch in each frame.
 * offset[b] = sync_epoch[b] - sync_epoch[ref] converts board b's ticks to
 * the reference board's time base; the aggregator then merges the streams
 * by aligned time, drops the copies of a packet heard by several boards and
 * emits one ordered stream.
 */

#define BH_MAX_BOARDS           256
#define BH_SYNC_HIST            4
#define BH_NO_HOST_TIME         INT64_MIN
#define BH_SYNC_PAIR_WINDOW_US  500000
#define BH_AGG_DEDUP_US         100         /* < T_IFS (150 µs), > inter-board error (~75 µs) */
#define BH_AGG_REORDER_US       300000      /* covers USB arrival skew between boards */
#define BH_AGG_PENDING_TIMEOUT_US 3000000   /* no SYNC in 3 s: degrade to raw ticks */

/** 32-bit circular signed difference a - b. */
int32_t bh_sdiff32(uint32_t a, uint32_t b);

/** board_id -> advertising channel it guards (0->37, 1->38, 2->39). */
bool bh_guard_channel_for_board(uint8_t board_id, uint8_t *channel);

typedef struct bh_sync_edge {
    uint32_t tick;
    int64_t  host_us;       /**< host arrival time, or BH_NO_HOST_TIME */
} bh_sync_edge;

/**
 * Aligns board clocks to the reference board using reported SYNC edges.
 *
 * The two reports of one physical edge reach the host over separate serial
 * ports and can arrive hundreds of ms apart, so ticks are paired by host
 * arrival time (within pair_window_us) rather than "latest with latest",
 * which would mispair by one heartbeat period when a board's new edge
 * arrives first. Without host times it degrades to latest-with-latest.
 */
typedef struct bh_sync_clock {
    uint8_t      ref_board;
    int64_t      pair_window_us;
    bh_sync_edge hist[BH_MAX_BOARDS][BH_SYNC_HIST];
    uint8_t      hist_len[BH_MAX_BOARDS];
    uint32_t     offset[BH_MAX_BOARDS];
    bool         has_offset[BH_MAX_BOARDS];
} bh_sync_clock;

void bh_sync_clock_init(bh_sync_clock *c, uint8_t ref_board, int64_t pair_window_us);

/** Record a board's most recent SYNC edge tick (0 = none yet, ignored). */
void bh_sync_clock_observe(bh_sync_clock *c, uint8_t board_id, uint32_t tick, int64_t host_us);

/** @return false while the board's offset to the reference is unknown. */
bool bh_sync_clock_offset(const bh_sync_clock *c, uint8_t board_id, uint32_t *offset);

/** Convert a board tick to the reference time base. @return false if unknown. */
bool bh_sync_clock_to_ref(const bh_sync_clock *c, uint8_t board_id, uint32_t tick, uint32_t *ref_tick);

/** A captured packet with its own copy of the PDU, as stored by the aggregator. */
typedef struct bh_agg_packet {
    uint32_t ts_us;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  phy;
    uint32_t access_addr;
    uint32_t crc;
    bool     crc_ok;
    uint8_t  board_id;
    uint32_t sync_epoch;
    int64_t  host_us;       /**< host arrival time, or BH_NO_HOST_TIME */
    uint8_t  pdu_len;
    uint8_t  pdu[BH_MAX_PDU_LEN];
    /* Filled in on output. */
    uint32_t aligned;       /**< reference-board tick */
    uint64_t key64;         /**< aligned tick with wraps unrolled; use for ordering and timestamps */
} bh_agg_packet;

void bh_agg_packet_from(bh_agg_packet *dst, const bh_packet *src, int64_t host_us);

/** Borrowed view of an aggregated packet, e.g. for bh_btle_rf_record(). */
void bh_agg_packet_view(const bh_agg_packet *src, bh_packet *view);

typedef void (*bh_agg_emit_cb)(void *ctx, const bh_agg_packet *pkt);

typedef struct bh_aggregator bh_aggregator;

/**
 * Create an aggregator. Packets are held in a reorder buffer until
 * reorder_window_us has passed (in aligned time) and duplicates seen by
 * several boards within dedup_window_us are dropped on output.
 */
bh_aggregator *bh_aggregator_new(uint32_t dedup_window_us, uint32_t reorder_window_us, uint8_t ref_board);
void bh_aggregator_free(bh_aggregator *a);

/**
 * Feed one packet from any board; @p cb receives the packets that are now
 * safe to emit, in order. Packets from a board whose clock offset is still
 * unknown are held back (up to BH_AGG_PENDING_TIMEOUT_US) so that raw ticks
 * never leak into the aligned stream. @p cb must not call back into @p a.
 */
void bh_aggregator_add(bh_aggregator *a, const bh_agg_packet *pkt, bh_agg_emit_cb cb, void *ctx);

/** Emit everything still buffered, in order. */
void bh_aggregator_flush(bh_aggregator *a, bh_agg_emit_cb cb, void *ctx);

const bh_sync_clock *bh_aggregator_clock(const bh_aggregator *a);

/* ------------------------------------------------------- follow relay */

#define BH_ADV_ACCESS_ADDR      0x8E89BED6u
#define BH_FOLLOW_PARAMS_LEN    25
#define BH_RELAY_TTL_US         5000000     /* relay a given connection once per 5 s */

/** CONNECT_IND fields needed to follow the connection. */
typedef struct bh_connect_ind {
    uint32_t aa;
    uint32_t crc_init;
    uint8_t  win_size;
    uint16_t win_offset;
    uint16_t interval;
    uint16_t latency;
    uint16_t timeout;
    uint8_t  chan_map[5];
    uint8_t  hop;
    bool     csa2;
    uint8_t  adva[6];       /**< air (little-endian) order */
} bh_connect_ind;

/**
 * A CONNECT_IND on a primary advertising channel. AUX_CONNECT_REQ on a
 * secondary channel shares the PDU type but has a different txWinDelay and
 * PHY, so it is deliberately not matched.
 */
bool bh_is_connect_ind(const bh_packet *pkt);
bool bh_parse_connect_ind(const uint8_t *pdu, size_t len, bh_connect_ind *ci);

/** BH_CMD_FOLLOW argument (25 bytes); frame it with bh_cmd_build(). */
void bh_follow_params(const bh_connect_ind *ci, uint32_t anchor0_us, uint8_t out[BH_FOLLOW_PARAMS_LEN]);

/**
 * Callback that delivers a FOLLOW command to a board.
 * @return true if it was sent.
 */
typedef bool (*bh_relay_send_cb)(void *ctx, uint8_t board_id, const uint8_t *params, size_t params_len);

typedef struct bh_relay_stats {
    uint32_t relayed;
    uint32_t sent_cmds;
    uint32_t skipped_no_offset;
    uint32_t skipped_dup;
    uint32_t skipped_target;
} bh_relay_stats;

/**
 * When one board captures a CONNECT_IND, hands the connection to the other
 * boards (anchor converted to each board's own clock) so that all of them
 * follow it; the aggregator then dedups. Not thread-safe: the caller locks.
 */
typedef struct bh_follow_relay {
    bh_sync_clock  clock;
    bool           has_target;
    uint8_t        target[6];
    bool           registered[BH_MAX_BOARDS];
    struct {
        bool     used;
        uint32_t aa;
        int64_t  host_us;
    } relayed[64];
    bh_relay_stats stats;
} bh_follow_relay;

/** @p target_le: 6-byte AdvA in air order to relay only that device, or NULL. */
void bh_follow_relay_init(bh_follow_relay *r, uint8_t ref_board, const uint8_t *target_le);
void bh_follow_relay_register(bh_follow_relay *r, uint8_t board_id);
void bh_follow_relay_observe(bh_follow_relay *r, uint8_t board_id, uint32_t sync_epoch, int64_t host_us);

/**
 * Event-0 anchor of a CONNECT_IND captured by @p from_board, in @p to_board's
 * clock. @p payload_len is the PDU header length byte.
 */
bool bh_follow_relay_anchor0(const bh_follow_relay *r, uint8_t from_board, uint32_t ts_us,
                             uint8_t payload_len, uint16_t win_offset, uint8_t to_board,
                             uint32_t *anchor0_us);

/** @return the number of boards the connection was relayed to. */
int bh_follow_relay_maybe_relay(bh_follow_relay *r, uint8_t from_board, const bh_packet *pkt,
                                int64_t host_us, bh_relay_send_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* BLEHOUND_H */
