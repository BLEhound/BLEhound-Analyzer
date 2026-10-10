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
#define BH_FRAME_STATUS             0x02
#define BH_FRAME_SYNC               0x03    /* SYNC heartbeat: board_id, sync_count, sync_epoch */

/* Host -> device commands. */
#define BH_CMD_SET_CHANNEL          0x81    /* 1 byte: BLE channel index */
#define BH_CMD_SET_TARGET           0x84    /* 6 bytes: AdvA little-endian, all zero = no filter */
#define BH_CMD_SET_HOPPING          0x85    /* 1 byte: 1 = hop 37/38/39 */
#define BH_CMD_FOLLOW               0x86
#define BH_CMD_SET_SINGLE_TARGET    0x87    /* 1 byte: 1 = single-target (default), 0 = multi-target */
#define BH_CMD_QUERY_STATUS         0x88    /* no args; device replies with a BH_FRAME_STATUS frame */
#define BH_CMD_LL_CTRL_HINT         0x8A    /* aa(4 LE) + plaintext LL data PDU (header + payload, MIC
                                             * stripped): a control PDU the host decrypted, so the device
                                             * can apply channel-map / connection / PHY updates at their
                                             * instant even though the link is encrypted. */
#define BH_CMD_SET_IRK              0x89    /* 16 bytes: target IRK, air/SMP order (LSO first); all zero = clear.
                                             * The device then recognises the target's rotating resolvable
                                             * private addresses and keeps following it. */

/* STATUS frame flags. */
#define BH_STATUS_SINGLE_TARGET     (1u << 0)
#define BH_STATUS_HOPPING           (1u << 1)
#define BH_STATUS_TARGET_SET        (1u << 2)
#define BH_STATUS_FOLLOWING         (1u << 3)
#define BH_STATUS_SYNC_ACTIVE       (1u << 4)
#define BH_STATUS_IRK_SET           (1u << 5)

#define BH_FW_VERSION_MAX           64

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
    uint8_t        direction;    /**< BH_DIR_*: from the dongle's place in the connection event */
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

/** Device status, from a BH_FRAME_STATUS reply to BH_CMD_QUERY_STATUS. */
typedef struct bh_status {
    uint8_t  status_version;
    uint8_t  board_id;
    uint8_t  guard_channel;
    uint8_t  flags;             /**< BH_STATUS_* */
    uint32_t sync_count;
    uint32_t connects_seen;
    uint8_t  active_now;
    char     fw_version[BH_FW_VERSION_MAX];
} bh_status;

/**
 * Parse a decoded device frame as a status frame.
 * @return false if it is not a well-formed BH_FRAME_STATUS.
 */
bool bh_parse_status(const uint8_t *raw, size_t len, bh_status *st);

/** SYNC heartbeat: sent after every SYNC edge whether or not packets pass the target filter. */
typedef struct bh_sync_frame {
    uint8_t  board_id;
    uint32_t sync_count;
    uint32_t sync_epoch;    /**< the board's timer at that edge */
} bh_sync_frame;
bool bh_parse_sync(const uint8_t *raw, size_t len, bh_sync_frame *sf);

/**
 * Build a LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR record body:
 * BTLE_RF pseudo-header + access address [+ coding indicator] + PDU + CRC.
 * @return record length, or 0 if @p out_cap is too small.
 */
size_t bh_btle_rf_record(const bh_packet *pkt, uint8_t *out, size_t out_cap);

/* Extra BTLE_RF pseudo-header flags for bh_btle_rf_record_ex(). */
#define BH_RF_FLAG_DECRYPTED        0x0008
#define BH_RF_FLAG_MIC_CHECKED      0x1000
#define BH_RF_FLAG_MIC_VALID        0x2000
#define BH_RF_PDU_DATA_C2P          (2u << 7)
#define BH_RF_PDU_DATA_P2C          (3u << 7)

/** Same as bh_btle_rf_record() with extra pseudo-header flags OR-ed in. */
size_t bh_btle_rf_record_ex(const bh_packet *pkt, uint16_t extra_flags, uint8_t *out, size_t out_cap);
/** Flags describing a packet the decryptor handled: decrypted, MIC valid, direction. */
uint16_t bh_rf_flags_for_decrypted(uint8_t direction);

/* Byte 3 of the BTLE_RF pseudo-header (access address offenses) is unused while
 * BTLE_RF's AA-offenses-valid flag is clear; aggregated captures store the
 * receiving board there as board_id + 1 (0 = not recorded). */
#define BH_RF_BOARD_BYTE            3
/** Record which board heard the packet in a record built by bh_btle_rf_record*(). */
void bh_btle_rf_set_board(uint8_t *rec, uint8_t board_id);

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

/**
 * Parse @p len bytes of hex ("0A1B..." with optional ':', '-' or spaces).
 * @return false if the text is not exactly @p len bytes.
 */
bool bh_parse_hex(const char *text, uint8_t *out, size_t len);

/* --------------------------------------------------- privacy / crypto */

/** AES-128 single block, FIPS-197 byte order; @p in and @p out may alias. */
void bh_aes128_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/** Random address with the resolvable-private pattern (top two bits 01). */
bool bh_rpa_is_resolvable(const uint8_t addr_le[6]);

/**
 * ah() check: does @p irk_le resolve @p addr_le?
 * @param irk_le  16 bytes in air / SMP Identity Information order (LSO first)
 * @param addr_le 6 bytes in air (little-endian) order
 */
bool bh_rpa_matches(const uint8_t irk_le[16], const uint8_t addr_le[6]);

/**
 * AES-CCM as the BLE link layer uses it: 13-byte nonce, one AAD byte,
 * 4-byte MIC. @p ct/@p pt may alias.
 */
void bh_ccm_encrypt(const uint8_t sk[16], const uint8_t nonce[13], uint8_t aad,
                    const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t mic[4]);
/** @return true if the MIC verified; @p pt then holds the plaintext. */
bool bh_ccm_decrypt(const uint8_t sk[16], const uint8_t nonce[13], uint8_t aad,
                    const uint8_t *ct, size_t ct_len, const uint8_t mic[4], uint8_t *pt);

/* ------------------------------------------------- link-layer decryption */

#define BH_DECRYPT_MAX_LTKS     8
#define BH_DECRYPT_MAX_CONNS    4

#define BH_DIR_UNKNOWN              0
#define BH_DIR_CENTRAL_PERIPHERAL   1
#define BH_DIR_PERIPHERAL_CENTRAL   2

/** Encryption state of one followed connection. */
typedef struct bh_ll_crypto_conn {
    bool     used;
    uint32_t aa;
    uint32_t last_seq;
    uint8_t  skd[16];           /**< SKDs || SKDm, AES block order */
    uint8_t  iv[8];             /**< IVm || IVs, air order */
    bool     have_skdm, have_skds;
    uint8_t  sk_cand[BH_DECRYPT_MAX_LTKS][16];
    int      n_cand;
    bool     sk_confirmed;
    uint8_t  sk[16];
    bool     encrypted;
    uint64_t counter[2];        /**< next expected packet counter, [0]=central->peripheral */
} bh_ll_crypto_conn;

typedef struct bh_decrypt_stats {
    uint32_t sessions;          /**< SKD/IV pairs seen (session keys derived) */
    uint32_t decrypted;
    uint32_t failed;            /**< encrypted PDUs no key/counter verified */
} bh_decrypt_stats;

typedef struct bh_decryptor {
    uint8_t  ltk[BH_DECRYPT_MAX_LTKS][16];   /**< AES key order */
    int      n_ltk;
    uint32_t seq;
    bh_ll_crypto_conn conns[BH_DECRYPT_MAX_CONNS];
    bh_decrypt_stats stats;
} bh_decryptor;

void bh_decryptor_init(bh_decryptor *d);
void bh_decryptor_clear_ltks(bh_decryptor *d);
/** @p ltk_le: 16 bytes in air / SMP order (LSO first). @return false when full. */
bool bh_decryptor_add_ltk(bh_decryptor *d, const uint8_t ltk_le[16]);
/**
 * Feed one captured packet (advertising packets are ignored). When the
 * packet decrypts, its PDU is replaced by the plaintext written to @p buf
 * (MIC stripped, length adjusted) and @p direction says who sent it.
 * @return true if the packet was decrypted.
 */
bool bh_decryptor_process(bh_decryptor *d, bh_packet *pkt, uint8_t *buf, size_t cap, uint8_t *direction);

/**
 * After a successful bh_decryptor_process(): is this plaintext a control PDU
 * the device needs to know about (channel map, connection or PHY update)?
 */
bool bh_ll_ctrl_hint_wanted(const bh_packet *pkt);

/** Build the BH_CMD_LL_CTRL_HINT argument for @p pkt. @return length, 0 if it does not fit. */
size_t bh_ll_ctrl_hint_args(const bh_packet *pkt, uint8_t *out, size_t cap);

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
#define BH_AGG_DEDUP_US         130         /* < T_IFS (150 µs), > inter-board error (seen up to ~101 µs) */
#define BH_AGG_REORDER_US       300000      /* covers USB arrival skew between boards */
#define BH_AGG_PENDING_TIMEOUT_US 3000000   /* no SYNC in 3 s: degrade to raw ticks */
/* While a board's offset goes unconfirmed its clock drifts away from the
 * reference (a few ppm between two crystals), so copies heard by different
 * boards drift apart; the dedup window grows with the offset's age at this
 * rate, up to the cap, which stays well below a connection interval. */
#define BH_AGG_STALE_DRIFT_PPM  20
#define BH_AGG_DEDUP_STALE_MAX_US 10000

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
    uint32_t     cand_offset[BH_MAX_BOARDS];   /**< an offset that disagrees with the established one */
    uint8_t      cand_hits[BH_MAX_BOARDS];     /**< how many times in a row it was seen */
    /* Diagnostics: when the offset was last confirmed, and how pairing went. */
    uint32_t     paired_ref_tick[BH_MAX_BOARDS]; /**< reference tick of the edge that last set/confirmed the offset */
    uint32_t     pair_ok[BH_MAX_BOARDS];       /**< pairings that set or confirmed the offset */
    uint32_t     pair_miss[BH_MAX_BOARDS];     /**< new edges with no reference edge inside the window */
    uint32_t     pair_reject[BH_MAX_BOARDS];   /**< pairings that disagreed with the offset (debounced) */
    uint32_t     switches[BH_MAX_BOARDS];      /**< offset replaced after consistent disagreement */
} bh_sync_clock;

#define BH_SYNC_OFFSET_TOL_US   20000      /* offsets closer than this are the same edge */
#define BH_SYNC_SWITCH_AFTER    2          /* consistent disagreements before adopting a new offset */

void bh_sync_clock_init(bh_sync_clock *c, uint8_t ref_board, int64_t pair_window_us);

/** Record a board's most recent SYNC edge tick (0 = none yet, ignored). */
void bh_sync_clock_observe(bh_sync_clock *c, uint8_t board_id, uint32_t tick, int64_t host_us);

/** @return false while the board's offset to the reference is unknown. */
bool bh_sync_clock_offset(const bh_sync_clock *c, uint8_t board_id, uint32_t *offset);

/** Convert a board tick to the reference time base. @return false if unknown. */
bool bh_sync_clock_to_ref(const bh_sync_clock *c, uint8_t board_id, uint32_t tick, uint32_t *ref_tick);

/**
 * How long ago, in reference time at @p ref_now, the board's offset was last
 * confirmed by a SYNC edge pair (0 for the reference board).
 * @return false while the offset is unknown.
 */
bool bh_sync_clock_offset_age(const bh_sync_clock *c, uint8_t board_id, uint32_t ref_now, uint32_t *age_us);

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
    uint8_t  direction;
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

/**
 * Feed a board's SYNC heartbeat (bh_sync_frame). Heartbeats come after every
 * edge even when no packet passes the board's filters, so offsets keep being
 * confirmed while the reference board, or any board, hears nothing.
 */
void bh_aggregator_observe_sync(bh_aggregator *a, uint8_t board_id, uint32_t sync_epoch, int64_t host_us,
                                bh_agg_emit_cb cb, void *ctx);

const bh_sync_clock *bh_aggregator_clock(const bh_aggregator *a);

typedef struct bh_agg_stats {
    uint64_t emitted;
    uint64_t duplicates;        /**< copies dropped */
    uint64_t duplicates_stale;  /**< ... of which only the widened (stale offset) window caught */
    uint64_t duplicates_bad_crc; /**< ... of which were CRC-failed copies matched by AA + channel + time */
    uint32_t max_window_us;     /**< widest dedup window used so far */
} bh_agg_stats;

void bh_aggregator_stats(const bh_aggregator *a, bh_agg_stats *out);

/* ------------------------------------------------------- follow relay */

#define BH_ADV_ACCESS_ADDR      0x8E89BED6u
#define BH_FOLLOW_PARAMS_LEN    25
#define BH_RELAY_TTL_US         5000000     /* relay a given connection once per 5 s */
#define BH_RELAY_RETRY_US       1000000     /* re-send FOLLOW to a board that has not picked up */
#define BH_RELAY_MAX_TRIES      4

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
    uint32_t retried;               /**< FOLLOW re-sent (late sync offset or board did not pick up) */
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
    bool           has_irk;         /**< also relay the target's resolvable private addresses */
    uint8_t        irk[16];
    bool           trust_source;    /**< the catching board already filtered: relay without checking AdvA */
    bool           registered[BH_MAX_BOARDS];
    struct {
        bool     used;
        uint32_t aa;
        int64_t  host_us;           /**< when the CONNECT_IND was seen */
        int64_t  last_try_us;
        uint8_t  tries;
        uint8_t  from_board;
        uint32_t ts_us;             /**< CONNECT_IND timestamp on from_board */
        uint8_t  payload_len;
        bh_connect_ind ci;
        bool     delivered[BH_MAX_BOARDS];  /**< FOLLOW written to that board */
        bool     seen[BH_MAX_BOARDS];       /**< that board has produced data frames for aa */
    } relayed[16];
    bh_relay_stats stats;
} bh_follow_relay;

/** Relay every CONNECT_IND the boards let through, without matching AdvA on the host. */
void bh_follow_relay_set_trust(bh_follow_relay *r, bool trust);
/** Note a data-channel frame: the board that sent it follows that connection. */
void bh_follow_relay_note_packet(bh_follow_relay *r, uint8_t board_id, const bh_packet *pkt);
/**
 * Re-send FOLLOW for recent connections to boards that could not be reached
 * (no sync offset yet) or have not produced any frame for them. Cheap; call often.
 * @return the number of commands sent.
 */
int bh_follow_relay_retry(bh_follow_relay *r, int64_t host_us, bh_relay_send_cb cb, void *ctx);

/** @p target_le: 6-byte AdvA in air order to relay only that device, or NULL. */
void bh_follow_relay_init(bh_follow_relay *r, uint8_t ref_board, const uint8_t *target_le);
void bh_follow_relay_register(bh_follow_relay *r, uint8_t board_id);
/** @p irk_le: the target's IRK (air order) so rotated addresses still count, or NULL to clear. */
void bh_follow_relay_set_irk(bh_follow_relay *r, const uint8_t *irk_le);
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


/* ---- USB DFU: SMP (mcumgr) over the firmware loader's CDC ACM port ------------------------
 *
 * The dongle firmware is MCUboot (firmware-loader mode) + a loader image + the sniffer app.
 * BH_CMD_ENTER_DFU on the capture port makes the app reboot into the loader, which enumerates
 * with BH_USB_PID_LOADER and speaks SMP over serial: packets are base64 lines with a 2-byte
 * marker (0x06 0x09 first frame, 0x04 0x14 continuation), carrying be16 length + SMP header +
 * CBOR payload + be16 CRC-16/XMODEM. The loader only writes image-0 (the app slot).
 */
#define BH_USB_PID_LOADER           0x5210
#define BH_USB_PRODUCT_LOADER       "BLEhound Loader"
#define BH_CMD_ENTER_DFU            0x8B    /* no args: reboot into the firmware loader */

#define BH_SMP_OP_READ              0
#define BH_SMP_OP_READ_RSP          1
#define BH_SMP_OP_WRITE             2
#define BH_SMP_OP_WRITE_RSP         3
#define BH_SMP_GROUP_OS             0
#define BH_SMP_GROUP_IMAGE          1
#define BH_SMP_ID_OS_RESET          5
#define BH_SMP_ID_OS_PARAMS         6
#define BH_SMP_ID_IMG_STATE         0
#define BH_SMP_ID_IMG_UPLOAD        1
#define BH_SMP_ID_IMG_ERASE         5

#define BH_SMP_HDR_LEN              8
#define BH_SMP_MAX_PACKET           1220    /* CONFIG_MCUMGR_TRANSPORT_NETBUF_SIZE in the loader */
#define BH_SMP_FRAME_MAX            127     /* MCUMGR_SERIAL_MAX_FRAME: marker + base64 + '\n' */
#define BH_SMP_FRAME_RAW            93      /* raw bytes per frame, (127 - 3) / 4 * 3 */
/* Serial bytes for one maximal packet: (2 + 1220 + 2) bytes -> 14 frames of 127. */
#define BH_SMP_MAX_ENCODED          (((BH_SMP_MAX_PACKET + 4 + BH_SMP_FRAME_RAW - 1) / BH_SMP_FRAME_RAW) * BH_SMP_FRAME_MAX)
#define BH_SMP_DEFAULT_BUF_SIZE     256     /* assumed when the loader does not answer the params request */
/* Pause between serial lines when sending. The loader keeps only CONFIG_UART_MCUMGR_RX_BUF_COUNT (2)
 * 128-byte line buffers and drops lines that arrive before its work queue decoded the previous ones,
 * so a multi-line upload packet sent back to back never completes and gets no reply. */
#define BH_SMP_LINE_DELAY_US        2000

typedef struct bh_smp_hdr {
    uint8_t  op;
    uint8_t  flags;
    uint16_t len;       /**< payload (CBOR) length */
    uint16_t group;
    uint8_t  seq;
    uint8_t  id;
} bh_smp_hdr;

/** CRC-16/XMODEM (poly 0x1021, init 0), the checksum mcumgr serial uses. */
uint16_t bh_crc16_xmodem(uint16_t seed, const uint8_t *data, size_t len);

/** Encode header + CBOR payload into serial line bytes. @return bytes written, 0 if out_cap is too small. */
size_t bh_smp_encode(const bh_smp_hdr *hdr, const uint8_t *payload, size_t payload_len,
                     uint8_t *out, size_t out_cap);

typedef void (*bh_smp_packet_cb)(void *ctx, const bh_smp_hdr *hdr, const uint8_t *payload, size_t len);

typedef struct bh_smp_deframer {
    uint8_t line[BH_SMP_FRAME_MAX + 1];
    size_t  line_len;
    uint8_t pkt[BH_SMP_MAX_PACKET + 4];
    size_t  pkt_len;
    size_t  expect_len;     /**< from the be16 length field, 0 = no packet in progress */
} bh_smp_deframer;

void bh_smp_deframer_init(bh_smp_deframer *d);
/** Feed serial bytes; @p cb is called once per complete, CRC-valid packet. Bad frames are dropped. */
void bh_smp_deframer_feed(bh_smp_deframer *d, const uint8_t *data, size_t len,
                          bh_smp_packet_cb cb, void *ctx);

/** Largest image chunk whose upload request still fits a packet of @p buf_size bytes. */
size_t bh_smp_upload_chunk_max(size_t buf_size);

/* Request builders: each writes the complete serial line bytes and returns their length (0 = too small). */
size_t bh_smp_req_params(uint8_t seq, uint8_t *out, size_t out_cap);
size_t bh_smp_req_image_state(uint8_t seq, uint8_t *out, size_t out_cap);
size_t bh_smp_req_reset(uint8_t seq, uint8_t *out, size_t out_cap);
/** First chunk (off == 0) also carries the total image length. */
size_t bh_smp_req_image_upload(uint8_t seq, uint32_t off, uint32_t total_len,
                               const uint8_t *data, size_t data_len, uint8_t *out, size_t out_cap);

/* Response parsers (CBOR payload of a packet). */
/** "rc" (0 when absent) and "off" (unchanged when absent). @return false if the payload is not a CBOR map. */
bool bh_smp_rsp_status(const uint8_t *cbor, size_t len, int32_t *rc, uint32_t *off);
bool bh_smp_rsp_params(const uint8_t *cbor, size_t len, uint32_t *buf_size, uint32_t *buf_count);

typedef struct bh_smp_image {
    uint8_t slot;
    char    version[32];
    uint8_t hash[32];
    bool    has_hash;
    bool    bootable;
    bool    active;
    bool    confirmed;
    bool    pending;
} bh_smp_image;
/** @return number of images parsed from an image-state response, -1 on malformed input. */
int bh_smp_rsp_images(const uint8_t *cbor, size_t len, bh_smp_image *out, size_t max_images);

#ifdef __cplusplus
}
#endif

#endif /* BLEHOUND_H */
