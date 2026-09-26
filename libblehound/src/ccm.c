/* ccm.c
 * AES-CCM as the BLE link layer uses it (BT Core Spec Vol 6, Part E §2):
 * 13-byte nonce, 4-byte MIC, 2-byte length field, one byte of additional
 * data (the first header octet with NESN, SN and MD masked).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "blehound/blehound.h"

#include <string.h>

/* B0 flags: Adata=1, M=4 -> (4-2)/2=1, L=2 -> L-1=1 */
#define CCM_B0_FLAGS   0x49
/* counter block flags: L-1 */
#define CCM_CTR_FLAGS  0x01

static void xor_block(uint8_t *x, const uint8_t *y, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        x[i] ^= y[i];
    }
}

static void ccm_mac(const uint8_t sk[16], const uint8_t nonce[13], uint8_t aad,
                    const uint8_t *pt, size_t pt_len, uint8_t mac[16])
{
    uint8_t blk[16];

    /* B0 */
    blk[0] = CCM_B0_FLAGS;
    memcpy(blk + 1, nonce, 13);
    blk[14] = (uint8_t)(pt_len >> 8);
    blk[15] = (uint8_t)pt_len;
    bh_aes128_encrypt(sk, blk, mac);

    /* B1: AAD length (0x0001) + the AAD byte, zero padded */
    memset(blk, 0, sizeof(blk));
    blk[1] = 0x01;
    blk[2] = aad;
    xor_block(mac, blk, 16);
    bh_aes128_encrypt(sk, mac, mac);

    /* payload blocks */
    for (size_t off = 0; off < pt_len; off += 16) {
        size_t n = pt_len - off < 16 ? pt_len - off : 16;

        memset(blk, 0, sizeof(blk));
        memcpy(blk, pt + off, n);
        xor_block(mac, blk, 16);
        bh_aes128_encrypt(sk, mac, mac);
    }
}

static void ccm_ctr(const uint8_t sk[16], const uint8_t nonce[13], uint16_t index, uint8_t out[16])
{
    uint8_t blk[16];

    blk[0] = CCM_CTR_FLAGS;
    memcpy(blk + 1, nonce, 13);
    blk[14] = (uint8_t)(index >> 8);
    blk[15] = (uint8_t)index;
    bh_aes128_encrypt(sk, blk, out);
}

static void ccm_crypt(const uint8_t sk[16], const uint8_t nonce[13],
                      const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t ks[16];

    for (size_t off = 0; off < len; off += 16) {
        size_t n = len - off < 16 ? len - off : 16;

        ccm_ctr(sk, nonce, (uint16_t)(off / 16 + 1), ks);
        for (size_t i = 0; i < n; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        }
    }
}

void bh_ccm_encrypt(const uint8_t sk[16], const uint8_t nonce[13], uint8_t aad,
                    const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t mic[4])
{
    uint8_t mac[16];
    uint8_t s0[16];

    ccm_mac(sk, nonce, aad, pt, pt_len, mac);
    ccm_ctr(sk, nonce, 0, s0);
    for (int i = 0; i < 4; i++) {
        mic[i] = (uint8_t)(mac[i] ^ s0[i]);
    }
    ccm_crypt(sk, nonce, pt, pt_len, ct);
}

bool bh_ccm_decrypt(const uint8_t sk[16], const uint8_t nonce[13], uint8_t aad,
                    const uint8_t *ct, size_t ct_len, const uint8_t mic[4], uint8_t *pt)
{
    uint8_t mac[16];
    uint8_t s0[16];
    uint8_t diff = 0;

    ccm_crypt(sk, nonce, ct, ct_len, pt);
    ccm_mac(sk, nonce, aad, pt, ct_len, mac);
    ccm_ctr(sk, nonce, 0, s0);
    for (int i = 0; i < 4; i++) {
        diff |= (uint8_t)(mic[i] ^ mac[i] ^ s0[i]);
    }
    return diff == 0;
}
