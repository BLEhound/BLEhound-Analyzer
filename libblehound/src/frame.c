/* frame.c
 * Device frame parsing, BTLE_RF record assembly and timestamp mapping.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "blehound/blehound.h"

#define FLAG_CRC_OK             0x01
#define FLAG_TRI                0x08    /* tri-board: board_id + sync_epoch follow the header */

/* BTLE_RF pseudo-header flags */
#define RF_FLAG_DEWHITENED      0x0001
#define RF_FLAG_SIGNAL_VALID    0x0002
#define RF_FLAG_REF_AA_VALID    0x0010
#define RF_FLAG_CRC_CHECKED     0x0400
#define RF_FLAG_CRC_VALID       0x0800
#define RF_FLAG_PHY_SHIFT       14

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
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

bool bh_parse_frame(const uint8_t *raw, size_t len, bh_packet *pkt)
{
    if (len < BH_FRAME_HEADER_LEN || raw[0] != BH_FRAME_PACKET) {
        return false;
    }

    uint8_t flags = raw[1];
    size_t off = BH_FRAME_HEADER_LEN;

    memset(pkt, 0, sizeof(*pkt));
    pkt->ts_us = get_le32(raw + 2);
    pkt->channel = raw[6];
    pkt->rssi = (int8_t)raw[7];
    pkt->phy = raw[8];
    pkt->access_addr = get_le32(raw + 9);
    pkt->crc = (uint32_t)raw[13] | (uint32_t)raw[14] << 8 | (uint32_t)raw[15] << 16;
    pkt->pdu_len = raw[16];
    pkt->crc_ok = (flags & FLAG_CRC_OK) != 0;

    if (flags & FLAG_TRI) {
        if (len < BH_FRAME_HEADER_LEN + BH_TRI_EXT_LEN) {
            return false;
        }
        pkt->board_id = raw[BH_FRAME_HEADER_LEN];
        pkt->sync_epoch = get_le32(raw + BH_FRAME_HEADER_LEN + 1);
        off += BH_TRI_EXT_LEN;
    }

    if (len - off != pkt->pdu_len) {
        return false;               /* length mismatch: drop */
    }
    pkt->pdu = raw + off;
    return true;
}

uint8_t bh_ble_to_rf_channel(uint8_t ble_channel)
{
    /* Advertising channels sit at the bottom, middle and top of the band. */
    switch (ble_channel) {
    case 37: return 0;              /* 2402 MHz */
    case 38: return 12;             /* 2426 MHz */
    case 39: return 39;             /* 2480 MHz */
    default:
        /* data 0..10 lie between 37 and 38, 11..36 between 38 and 39 */
        return ble_channel <= 10 ? ble_channel + 1 : ble_channel + 2;
    }
}

size_t bh_btle_rf_record(const bh_packet *pkt, uint8_t *out, size_t out_cap)
{
    uint8_t phy = pkt->phy > BH_PHY_CODED_S8 ? BH_PHY_CODED_S8 : pkt->phy;
    bool coded = pkt->phy == BH_PHY_CODED_S8 || pkt->phy == BH_PHY_CODED_S2;
    size_t need = 10 + 4 + (coded ? 1 : 0) + pkt->pdu_len + 3;
    uint16_t flags = RF_FLAG_DEWHITENED | RF_FLAG_SIGNAL_VALID |
                     RF_FLAG_REF_AA_VALID | RF_FLAG_CRC_CHECKED;
    size_t o = 0;

    if (need > out_cap) {
        return 0;
    }
    if (pkt->crc_ok) {
        flags |= RF_FLAG_CRC_VALID;
    }
    flags |= (uint16_t)(phy & 0x3) << RF_FLAG_PHY_SHIFT;

    /* BTLE_RF pseudo-header */
    out[o++] = bh_ble_to_rf_channel(pkt->channel);
    out[o++] = (uint8_t)pkt->rssi;
    out[o++] = 0;                   /* noise: not measured */
    out[o++] = 0;                   /* access address offenses: not tracked */
    put_le32(out + o, pkt->access_addr);
    o += 4;
    put_le16(out + o, flags);
    o += 2;

    /* Link-layer frame */
    put_le32(out + o, pkt->access_addr);
    o += 4;
    if (coded) {
        /* Coding Indicator: 0 = S8, 1 = S2 */
        out[o++] = pkt->phy == BH_PHY_CODED_S2 ? 1 : 0;
    }
    memcpy(out + o, pkt->pdu, pkt->pdu_len);
    o += pkt->pdu_len;
    out[o++] = (uint8_t)pkt->crc;
    out[o++] = (uint8_t)(pkt->crc >> 8);
    out[o++] = (uint8_t)(pkt->crc >> 16);
    return o;
}

void bh_ts_mapper_init(bh_ts_mapper *m, uint64_t host_epoch_us)
{
    memset(m, 0, sizeof(*m));
    m->host_epoch_us = host_epoch_us;
}

uint64_t bh_ts_mapper_map(bh_ts_mapper *m, uint32_t fw_us)
{
    if (!m->started) {
        m->started = true;
        m->first_fw_us = fw_us;
        m->prev_fw_us = fw_us;
    }
    if (fw_us < m->prev_fw_us) {
        m->wraps++;
    }
    m->prev_fw_us = fw_us;

    uint64_t elapsed = (uint64_t)fw_us + (m->wraps << 32) - m->first_fw_us;
    return m->host_epoch_us + elapsed;
}
