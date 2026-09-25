/* adv.c
 * Advertising PDU parsing for the device list.
 *
 * BT Core Spec Vol 6, Part B, 2.3 (advertising PDUs), 2.3.4 (extended
 * header); Core Spec Supplement Part A (AD types).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "blehound/blehound.h"

#define PDU_ADV_IND             0x0
#define PDU_ADV_DIRECT_IND      0x1
#define PDU_ADV_NONCONN_IND     0x2
#define PDU_SCAN_REQ            0x3
#define PDU_SCAN_RSP            0x4
#define PDU_CONNECT_IND         0x5
#define PDU_ADV_SCAN_IND        0x6
#define PDU_ADV_EXT_IND         0x7
#define PDU_AUX_CONNECT_RSP     0x8

#define HDR_TXADD               0x40
#define HDR_RXADD               0x80
#define EXT_FLAG_ADVA           0x01
#define EXT_ADV_MODE_CONNECTABLE 0x1

#define AD_SHORT_NAME           0x08
#define AD_COMPLETE_NAME        0x09
#define AD_MANUFACTURER         0xFF

static void parse_ad(const uint8_t *data, size_t len, bh_adv_info *info)
{
    size_t i = 0;

    while (i + 1 < len) {
        size_t ad_len = data[i];
        if (ad_len == 0 || i + 1 + ad_len > len) {
            break;                              /* padding or truncated */
        }
        uint8_t type = data[i + 1];
        const uint8_t *val = data + i + 2;
        size_t val_len = ad_len - 1;

        if ((type == AD_COMPLETE_NAME || type == AD_SHORT_NAME) &&
                (!info->has_name || (type == AD_COMPLETE_NAME && !info->name_complete))) {
            size_t n = val_len < BH_ADV_NAME_MAX - 1 ? val_len : BH_ADV_NAME_MAX - 1;
            memcpy(info->name, val, n);
            info->name[n] = '\0';
            info->has_name = true;
            info->name_complete = type == AD_COMPLETE_NAME;
        } else if (type == AD_MANUFACTURER && val_len >= 2 && !info->has_company) {
            info->company_id = (uint16_t)(val[0] | val[1] << 8);
            info->has_company = true;
        }
        i += 1 + ad_len;
    }
}

bool bh_adv_parse(const bh_packet *pkt, bh_adv_info *info)
{
    const uint8_t *pdu = pkt->pdu;
    size_t len = pkt->pdu_len;
    const uint8_t *adva = NULL;
    const uint8_t *ad = NULL;
    size_t ad_len = 0;

    memset(info, 0, sizeof(*info));
    if (pkt->access_addr != BH_ADV_ACCESS_ADDR || len < 2) {
        return false;
    }
    const uint8_t *payload = pdu + 2;
    size_t payload_len = len - 2;
    if (pdu[1] < payload_len) {
        payload_len = pdu[1];                   /* trust the header length */
    }
    info->pdu_type = pdu[0] & 0x0F;
    info->adva_random = (pdu[0] & HDR_TXADD) != 0;
    info->from_advertiser = true;

    switch (info->pdu_type) {
    case PDU_ADV_IND:
    case PDU_ADV_NONCONN_IND:
    case PDU_SCAN_RSP:
    case PDU_ADV_SCAN_IND:
        if (payload_len < 6) {
            return false;
        }
        adva = payload;
        ad = payload + 6;
        ad_len = payload_len - 6;
        info->connectable = info->pdu_type == PDU_ADV_IND;
        break;
    case PDU_ADV_DIRECT_IND:
        if (payload_len < 12) {
            return false;
        }
        adva = payload;                         /* then TargetA, no AdvData */
        info->connectable = true;
        break;
    case PDU_SCAN_REQ:
    case PDU_CONNECT_IND:
        if (payload_len < 12) {
            return false;
        }
        adva = payload + 6;                     /* ScanA/InitA first */
        info->adva_random = (pdu[0] & HDR_RXADD) != 0;
        info->from_advertiser = false;
        break;
    case PDU_ADV_EXT_IND:
    case PDU_AUX_CONNECT_RSP: {
        if (payload_len < 2) {
            return false;
        }
        size_t ext_len = payload[0] & 0x3F;
        uint8_t mode = payload[0] >> 6;
        if (ext_len < 1 + 6 || (payload[1] & EXT_FLAG_ADVA) == 0 || payload_len < 1 + ext_len) {
            return false;                       /* no AdvA in the extended header */
        }
        adva = payload + 2;
        ad = payload + 1 + ext_len;
        ad_len = payload_len - 1 - ext_len;
        info->extended = true;
        info->connectable = mode == EXT_ADV_MODE_CONNECTABLE;
        info->from_advertiser = info->pdu_type == PDU_ADV_EXT_IND;
        break;
    }
    default:
        return false;
    }

    memcpy(info->adva, adva, sizeof(info->adva));
    if (ad != NULL && ad_len > 0) {
        parse_ad(ad, ad_len, info);
    }
    return true;
}

enum bh_addr_kind bh_addr_kind(const uint8_t adva[6], bool random_addr)
{
    if (!random_addr) {
        return BH_ADDR_PUBLIC;
    }
    switch (adva[5] >> 6) {                     /* two most significant bits */
    case 0x3: return BH_ADDR_RANDOM_STATIC;
    case 0x1: return BH_ADDR_RANDOM_RESOLVABLE;
    default:  return BH_ADDR_RANDOM_NON_RESOLVABLE;
    }
}

void bh_format_mac(const uint8_t mac_le[6], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_le[5], mac_le[4], mac_le[3], mac_le[2], mac_le[1], mac_le[0]);
}
