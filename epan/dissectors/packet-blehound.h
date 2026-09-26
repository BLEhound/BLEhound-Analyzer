/* packet-blehound.h
 * Per-frame summary the BLEhound post-dissector taps out ("blehound") for
 * the transactions and connection panels.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BLEHOUND_H__
#define __PACKET_BLEHOUND_H__

#include <stdint.h>
#include <stdbool.h>
#include <wsutil/nstime.h>

#define BLEHOUND_KIND_ADV        0
#define BLEHOUND_KIND_EMPTY      1
#define BLEHOUND_KIND_LL_CTRL    2
#define BLEHOUND_KIND_L2CAP      3   /* start of an L2CAP PDU: cid / first byte valid */
#define BLEHOUND_KIND_L2CAP_CONT 4

#define BLEHOUND_DIR_UNKNOWN     0
#define BLEHOUND_DIR_C2P         1
#define BLEHOUND_DIR_P2C         2

typedef struct blehound_tap_info {
    uint32_t       frame_num;
    nstime_t       abs_ts;
    double         rel_ts;
    uint32_t       aa;
    uint8_t        channel;        /* BLE channel index 0..39 */
    int8_t         rssi;
    bool           crc_ok;
    bool           decrypted;
    uint8_t        direction;      /* BLEHOUND_DIR_* */
    uint8_t        kind;           /* BLEHOUND_KIND_* */
    uint8_t        adv_type;
    uint8_t        llid;
    uint8_t        ctrl_opcode;
    uint16_t       l2cap_cid;
    uint8_t        l2cap_opcode;   /* first byte of the L2CAP payload (ATT/SMP opcode, signalling code) */
    const uint8_t *payload;        /* highest-layer payload (packet scope) */
    unsigned       payload_len;
    /* CONNECT_IND */
    bool           connect_ind;
    uint8_t        inita[6];       /* air order */
    uint8_t        adva[6];
    uint32_t       conn_aa;
    uint8_t        win_size;
    uint16_t       win_offset, interval, latency, timeout;
    uint8_t        chan_map[5];
    uint8_t        hop;
    bool           csa2;
} blehound_tap_info_t;

#endif
