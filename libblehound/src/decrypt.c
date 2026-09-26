/* decrypt.c
 * Link-layer decryption of followed connections on the host.
 *
 * Watches LL_ENC_REQ / LL_ENC_RSP for SKD and IV, derives the session key
 * SK = e(LTK, SKDs || SKDm) for every LTK it holds, and from then on tries
 * to decrypt each data PDU that is long enough to carry a MIC. The first
 * MIC that verifies picks the LTK; after that the per-direction packet
 * counters are tracked, with a small search window so that packets the
 * sniffer missed (or retransmissions) do not derail the stream.
 *
 * Byte orders: LTK arrives in air / SMP order (LSO first) and is reversed
 * into the AES key; SKDm/SKDs/IVm/IVs are taken from the PDUs as they are
 * on the air. Verified against the sample data of BT Core Spec Vol 6, Part C.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "blehound/blehound.h"

#include <string.h>

#define LLID_CONTROL            0x03
#define LL_TERMINATE_IND        0x02
#define LL_ENC_REQ              0x03
#define LL_ENC_RSP              0x04
#define LL_START_ENC_REQ        0x05
#define LL_PAUSE_ENC_REQ        0x0A
#define LL_PAUSE_ENC_RSP        0x0B

#define LL_CONNECTION_UPDATE_IND 0x00
#define LL_CHANNEL_MAP_IND      0x01
#define LL_PHY_UPDATE_IND       0x18

#define MIC_LEN                 4
#define COUNTER_WINDOW          32      /* packets we may have missed in a row */
#define FIRST_PACKET_WINDOW     4       /* counters tried while the key is still unknown */

static bh_ll_crypto_conn *find_conn(bh_decryptor *d, uint32_t aa, bool create)
{
    bh_ll_crypto_conn *oldest = &d->conns[0];

    for (int i = 0; i < BH_DECRYPT_MAX_CONNS; i++) {
        bh_ll_crypto_conn *c = &d->conns[i];

        if (c->used && c->aa == aa) {
            return c;
        }
        if (!c->used) {
            oldest = c;
        } else if (oldest->used && c->last_seq < oldest->last_seq) {
            oldest = c;
        }
    }
    if (!create) {
        return NULL;
    }
    memset(oldest, 0, sizeof(*oldest));
    oldest->used = true;
    oldest->aa = aa;
    return oldest;
}

void bh_decryptor_init(bh_decryptor *d)
{
    memset(d, 0, sizeof(*d));
}

void bh_decryptor_clear_ltks(bh_decryptor *d)
{
    d->n_ltk = 0;
}

bool bh_decryptor_add_ltk(bh_decryptor *d, const uint8_t ltk_le[16])
{
    if (d->n_ltk >= BH_DECRYPT_MAX_LTKS) {
        return false;
    }
    for (int i = 0; i < 16; i++) {
        d->ltk[d->n_ltk][i] = ltk_le[15 - i];
    }
    d->n_ltk++;
    return true;
}

static void derive_candidates(bh_decryptor *d, bh_ll_crypto_conn *c)
{
    c->n_cand = 0;
    for (int k = 0; k < d->n_ltk && k < BH_DECRYPT_MAX_LTKS; k++) {
        bh_aes128_encrypt(d->ltk[k], c->skd, c->sk_cand[c->n_cand++]);
    }
    c->sk_confirmed = false;
    c->counter[0] = 0;
    c->counter[1] = 0;
    d->stats.sessions++;
}

static void build_nonce(const bh_ll_crypto_conn *c, uint64_t counter, int dir, uint8_t nonce[13])
{
    for (int i = 0; i < 5; i++) {
        nonce[i] = (uint8_t)(counter >> (8 * i));
    }
    nonce[4] = (uint8_t)((nonce[4] & 0x7F) | (dir == 0 ? 0x80 : 0x00));
    memcpy(nonce + 5, c->iv, 8);
}

static bool try_decrypt(const bh_ll_crypto_conn *c, const uint8_t sk[16], uint64_t counter, int dir,
                        const uint8_t *pdu, size_t pdu_len, uint8_t *out)
{
    uint8_t nonce[13];
    size_t ct_len = pdu_len - 2 - MIC_LEN;

    build_nonce(c, counter, dir, nonce);
    return bh_ccm_decrypt(sk, nonce, (uint8_t)(pdu[0] & 0xE3), pdu + 2, ct_len,
                          pdu + 2 + ct_len, out + 2);
}

/* Control PDUs the encryption setup is made of; all of them are plaintext. */
static void observe_control(bh_decryptor *d, bh_ll_crypto_conn *c, const uint8_t *pdu, size_t pdu_len)
{
    const uint8_t opcode = pdu[2];
    const uint8_t *p = pdu + 3;

    switch (opcode) {
    case LL_ENC_REQ:                /* Rand(8) EDIV(2) SKDm(8) IVm(4) */
        if (pdu_len < 2 + 1 + 22) {
            return;
        }
        for (int i = 0; i < 8; i++) {
            c->skd[8 + i] = p[10 + 7 - i];      /* SKDm is the low half of SKD */
        }
        memcpy(c->iv, p + 18, 4);
        c->have_skdm = true;
        c->have_skds = false;
        c->encrypted = false;
        c->sk_confirmed = false;
        c->n_cand = 0;
        break;
    case LL_ENC_RSP:                /* SKDs(8) IVs(4) */
        if (pdu_len < 2 + 1 + 12) {
            return;
        }
        for (int i = 0; i < 8; i++) {
            c->skd[i] = p[7 - i];               /* SKDs is the high half */
        }
        memcpy(c->iv + 4, p + 8, 4);
        c->have_skds = true;
        if (c->have_skdm) {
            derive_candidates(d, c);
        }
        break;
    case LL_START_ENC_REQ:
        c->encrypted = c->n_cand > 0;
        break;
    case LL_PAUSE_ENC_REQ:
    case LL_PAUSE_ENC_RSP:
    case LL_TERMINATE_IND:
        c->encrypted = false;
        break;
    default:
        break;
    }
}

bool bh_decryptor_process(bh_decryptor *d, bh_packet *pkt, uint8_t *buf, size_t cap, uint8_t *direction)
{
    if (direction) {
        *direction = BH_DIR_UNKNOWN;
    }
    if (pkt->access_addr == BH_ADV_ACCESS_ADDR || !pkt->crc_ok || pkt->pdu_len < 2) {
        return false;
    }
    const uint8_t *pdu = pkt->pdu;
    const size_t pdu_len = pkt->pdu_len;
    const uint8_t llid = pdu[0] & 0x03;
    bh_ll_crypto_conn *c = find_conn(d, pkt->access_addr, true);

    c->last_seq = ++d->seq;

    /* Plain control PDUs: only worth a look when they cannot be encrypted
     * (before the session exists) or when they are the pause/terminate ones. */
    if (llid == LLID_CONTROL && pdu_len >= 3 && !c->encrypted) {
        observe_control(d, c, pdu, pdu_len);
    }
    if (c->n_cand == 0 || pdu_len < 2 + 1 + MIC_LEN || cap < pdu_len - MIC_LEN) {
        return false;
    }

    /* Key not yet confirmed: try every candidate at the first few counters. */
    if (!c->sk_confirmed) {
        for (int k = 0; k < c->n_cand; k++) {
            for (uint64_t ctr = 0; ctr < FIRST_PACKET_WINDOW; ctr++) {
                for (int dir = 0; dir < 2; dir++) {
                    if (!try_decrypt(c, c->sk_cand[k], ctr, dir, pdu, pdu_len, buf)) {
                        continue;
                    }
                    memcpy(c->sk, c->sk_cand[k], 16);
                    c->sk_confirmed = true;
                    c->encrypted = true;
                    c->counter[dir] = ctr + 1;
                    goto done;
                }
            }
        }
        if (c->encrypted) {
            d->stats.failed++;
        }
        return false;
    }

    /* Expected counter first, then a retransmission, then the ones we may have missed. */
    for (int dir = 0; dir < 2; dir++) {
        uint64_t base = c->counter[dir];

        for (int step = -1; step <= COUNTER_WINDOW; step++) {
            if (step < 0 && base == 0) {
                continue;
            }
            uint64_t ctr = (uint64_t)((int64_t)base + step);

            if (try_decrypt(c, c->sk, ctr, dir, pdu, pdu_len, buf)) {
                c->counter[dir] = ctr + 1;
                goto done_dir;
            }
        }
        continue;
done_dir:
        c->encrypted = true;
        if (direction) {
            *direction = dir == 0 ? BH_DIR_CENTRAL_PERIPHERAL : BH_DIR_PERIPHERAL_CENTRAL;
        }
        goto finish;
    }
    d->stats.failed++;
    return false;

done:
    if (direction) {
        /* counter[dir] was set for the direction that verified */
        *direction = c->counter[0] > 0 ? BH_DIR_CENTRAL_PERIPHERAL : BH_DIR_PERIPHERAL_CENTRAL;
    }
finish:
    buf[0] = pdu[0];
    buf[1] = (uint8_t)(pdu[1] - MIC_LEN);
    pkt->pdu = buf;
    pkt->pdu_len = (uint8_t)(pdu_len - MIC_LEN);
    d->stats.decrypted++;

    /* Control PDUs inside the encrypted stream can end it. */
    if ((buf[0] & 0x03) == LLID_CONTROL && pkt->pdu_len >= 3) {
        uint8_t op = buf[2];

        if (op == LL_PAUSE_ENC_REQ || op == LL_PAUSE_ENC_RSP || op == LL_TERMINATE_IND) {
            c->encrypted = false;
            c->n_cand = 0;
            c->sk_confirmed = false;
        }
    }
    return true;
}

bool bh_ll_ctrl_hint_wanted(const bh_packet *pkt)
{
    if (pkt->access_addr == BH_ADV_ACCESS_ADDR || pkt->pdu_len < 3 || (pkt->pdu[0] & 0x03) != LLID_CONTROL) {
        return false;
    }
    switch (pkt->pdu[2]) {
    case LL_CONNECTION_UPDATE_IND:
    case LL_CHANNEL_MAP_IND:
    case LL_PHY_UPDATE_IND:
        return true;
    default:
        return false;
    }
}

size_t bh_ll_ctrl_hint_args(const bh_packet *pkt, uint8_t *out, size_t cap)
{
    if (cap < 4u + pkt->pdu_len) {
        return 0;
    }
    out[0] = (uint8_t)pkt->access_addr;
    out[1] = (uint8_t)(pkt->access_addr >> 8);
    out[2] = (uint8_t)(pkt->access_addr >> 16);
    out[3] = (uint8_t)(pkt->access_addr >> 24);
    memcpy(out + 4, pkt->pdu, pkt->pdu_len);
    return 4u + pkt->pdu_len;
}
