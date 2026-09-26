/* packet-blehound.c
 * BLEhound payload summary: a post-dissector that exposes, for every
 * Bluetooth LE LL frame, the payload of the highest layer the frame
 * carries (ATT/SMP PDU, LL control PDU, advertising data) as bytes and
 * as an "N bytes (xx xx …)" string for a packet-list column.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/tap.h>
#include <wiretap/wtap.h>

#include "packet-blehound.h"

void proto_register_blehound(void);
void proto_reg_handoff_blehound(void);

static int proto_blehound;
static int hf_blehound_payload;
static int hf_blehound_payload_summary;
static int hf_blehound_payload_len;
static int ett_blehound;
static int blehound_tap;

#define BLE_ADV_ACCESS_ADDR   0x8E89BED6
#define RF_HEADER_LEN         10
#define SUMMARY_MAX_BYTES     16

static int
dissect_blehound(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (pinfo->rec->rec_type != REC_TYPE_PACKET ||
        pinfo->rec->rec_header.packet_header.pkt_encap != WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR) {
        return 0;
    }
    unsigned total = tvb_captured_length(tvb);
    if (total < RF_HEADER_LEN + 4 + 2 + 3) {
        return 0;
    }
    uint16_t flags = tvb_get_letohs(tvb, 8);
    unsigned off = RF_HEADER_LEN + 4;
    if (((flags >> 14) & 0x3) == 2) {
        off++;                                  /* coded PHY: coding indicator */
    }
    uint32_t aa = tvb_get_letohl(tvb, RF_HEADER_LEN);
    uint8_t hdr = tvb_get_uint8(tvb, off);
    uint8_t len = tvb_get_uint8(tvb, off + 1);
    unsigned pstart = off + 2;
    unsigned pend = total - 3;                  /* CRC */
    if (pstart + len > pend) {
        return 0;
    }
    unsigned plen = len;
    /* Taps are pushed after this function returns: the record must outlive
     * the call, so it lives in the packet's pool. */
    blehound_tap_info_t *ip = wmem_new0(pinfo->pool, blehound_tap_info_t);
#define info (*ip)
    info.frame_num = pinfo->num;
    info.abs_ts = pinfo->abs_ts;
    info.rel_ts = nstime_to_sec(&pinfo->rel_ts);
    info.aa = aa;
    info.rssi = (int8_t)tvb_get_uint8(tvb, 1);
    info.crc_ok = (flags & 0x0800) != 0;
    info.decrypted = (flags & 0x0008) != 0;
    switch ((flags >> 7) & 0x7) {
    case 2: info.direction = BLEHOUND_DIR_C2P; break;
    case 3: info.direction = BLEHOUND_DIR_P2C; break;
    default: info.direction = BLEHOUND_DIR_UNKNOWN; break;
    }
    {
        uint8_t rf = tvb_get_uint8(tvb, 0);
        info.channel = rf == 0 ? 37 : rf == 12 ? 38 : rf == 39 ? 39 : rf <= 11 ? rf - 1 : rf - 2;
    }
    info.llid = hdr & 0x03;

    if (aa == BLE_ADV_ACCESS_ADDR) {
        uint8_t type = hdr & 0x0F;
        info.kind = BLEHOUND_KIND_ADV;
        info.adv_type = type;
        /* ADV_IND / ADV_NONCONN_IND / SCAN_RSP / ADV_SCAN_IND: AdvA then data */
        if ((type == 0x00 || type == 0x02 || type == 0x04 || type == 0x06) && plen >= 6) {
            pstart += 6;
            plen -= 6;
        }
        if (type == 0x05 && len >= 34) {
            const uint8_t *p = tvb_get_ptr(tvb, off + 2, 34);
            info.connect_ind = true;
            memcpy(info.inita, p, 6);
            memcpy(info.adva, p + 6, 6);
            info.conn_aa = (uint32_t)p[12] | (uint32_t)p[13] << 8 | (uint32_t)p[14] << 16 | (uint32_t)p[15] << 24;
            info.win_size = p[19];
            info.win_offset = (uint16_t)(p[20] | p[21] << 8);
            info.interval = (uint16_t)(p[22] | p[23] << 8);
            info.latency = (uint16_t)(p[24] | p[25] << 8);
            info.timeout = (uint16_t)(p[26] | p[27] << 8);
            memcpy(info.chan_map, p + 28, 5);
            info.hop = p[33] & 0x1F;
            info.csa2 = (hdr & 0x20) != 0;
        }
    } else {
        uint8_t llid = hdr & 0x03;
        if (plen == 0) {
            info.kind = BLEHOUND_KIND_EMPTY;
        } else if (llid == 0x03) {
            info.kind = BLEHOUND_KIND_LL_CTRL;
            info.ctrl_opcode = tvb_get_uint8(tvb, pstart);
        } else if (llid == 0x02 && plen >= 4) {
            info.kind = BLEHOUND_KIND_L2CAP;
            info.l2cap_cid = tvb_get_letohs(tvb, pstart + 2);
            info.l2cap_opcode = plen > 4 ? tvb_get_uint8(tvb, pstart + 4) : 0;
            pstart += 4;                        /* L2CAP start fragment: skip the L2CAP header */
            plen -= 4;
        } else {
            info.kind = BLEHOUND_KIND_L2CAP_CONT;
        }
    }
    if (plen > 0) {
        info.payload = tvb_get_ptr(tvb, pstart, plen);
        info.payload_len = plen;
    }
    tap_queue_packet(blehound_tap, pinfo, ip);
#undef info
    if (plen == 0) {
        return 0;
    }

    proto_item *ti = proto_tree_add_item(tree, proto_blehound, tvb, pstart, plen, ENC_NA);
    proto_tree *sub = proto_item_add_subtree(ti, ett_blehound);
    proto_tree_add_uint(sub, hf_blehound_payload_len, tvb, pstart, plen, plen);
    proto_tree_add_item(sub, hf_blehound_payload, tvb, pstart, plen, ENC_NA);

    wmem_strbuf_t *sb = wmem_strbuf_new(pinfo->pool, "");
    wmem_strbuf_append_printf(sb, "%u bytes (", plen);
    unsigned shown = plen < SUMMARY_MAX_BYTES ? plen : SUMMARY_MAX_BYTES;
    for (unsigned i = 0; i < shown; i++) {
        wmem_strbuf_append_printf(sb, i ? " %02X" : "%02X", tvb_get_uint8(tvb, pstart + i));
    }
    wmem_strbuf_append(sb, plen > shown ? " …)" : ")");
    proto_item *si = proto_tree_add_string(sub, hf_blehound_payload_summary, tvb, pstart, plen,
                                           wmem_strbuf_get_str(sb));
    proto_item_set_generated(si);
    return (int)plen;
}

void
proto_register_blehound(void)
{
    static hf_register_info hf[] = {
        { &hf_blehound_payload,
          { "Payload", "blehound.payload", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Payload of the highest layer this frame carries", HFILL } },
        { &hf_blehound_payload_len,
          { "Payload Length", "blehound.payload_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_blehound_payload_summary,
          { "Payload Summary", "blehound.payload_summary", FT_STRING, BASE_NONE, NULL, 0x0,
            "Length and first bytes of the payload, for the packet list", HFILL } },
    };
    static int *ett[] = { &ett_blehound };

    proto_blehound = proto_register_protocol("BLEhound payload", "BLEhound", "blehound");
    proto_register_field_array(proto_blehound, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("blehound", dissect_blehound, proto_blehound);
    blehound_tap = register_tap("blehound");
}

void
proto_reg_handoff_blehound(void)
{
    dissector_handle_t handle = find_dissector("blehound");
    register_postdissector(handle);
}
