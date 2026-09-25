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
} bh_ts_mapper;

void bh_ts_mapper_init(bh_ts_mapper *m, uint64_t host_epoch_us);

/** Packets must be mapped in arrival order; a backwards step is a wrap. */
uint64_t bh_ts_mapper_map(bh_ts_mapper *m, uint32_t fw_us);

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

#ifdef __cplusplus
}
#endif

#endif /* BLEHOUND_H */
