
#include "api.h"
#include "r5_parameter_sets.h"
#include "r5_cca_kem.h"
#include "shake.h"
#include <openssl/evp.h>

static int round5_dem(uint8_t *c2, size_t *c2_len, const uint8_t *key, const uint8_t *m, const size_t m_len) {
    int result = 1;
    int len;
    int c2length;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t final_key_iv[32 + 12];
    uint8_t tag[16];
    const uint8_t * const iv = final_key_iv + PARAMS_KAPPA_BYTES;

    /* Hash key to obtain final key and IV */
    shake256(final_key_iv, (size_t) (PARAMS_KAPPA_BYTES + 12), key, PARAMS_KAPPA_BYTES);

    /* Initialise AES GCM */
    int res = 1;
    res = !(ctx = EVP_CIPHER_CTX_new()) || (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, final_key_iv, iv) != 1);
    if (res) {
        goto done_dem;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); /* Disable padding */

    /* Encrypt message into c2 */
    if (EVP_EncryptUpdate(ctx, c2, &len, m, (int) m_len) != 1) {
        goto done_dem;
    }
    c2length = len;

    /* Finalise encrypt */
    if (EVP_EncryptFinal_ex(ctx, c2 + c2length, &len) != 1) {
        goto done_dem;
    }
    c2length += len;

    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        goto done_dem;
    }

    /* Append tag and IV */
    copy_u8(c2 + c2length, tag, 16);
    c2length += 16;

    /* Set total length */
    *c2_len = (size_t) c2length;

    /* All OK */
    result = 0;

done_dem:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

static int round5_dem_inverse(uint8_t *m, size_t *m_len, const uint8_t *key, const uint8_t *c2, const size_t c2_len) {
    int result = 1;
    int len;
    int m_length;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t final_key_iv[32 + 12];
    uint8_t tag[16];
    const size_t c2_len_no_tag = c2_len - 16U;
    const uint8_t * const iv = final_key_iv + PARAMS_KAPPA_BYTES;
    int ret;
    uint8_t * tmp_m;
    ptrdiff_t diff;
    int res = 1;

    /* Check length, must at least be as long as the tag (16 bytes).
     * Note that this is should already have been checked when calling this
     * function, so this is just an additional sanity check. */
    if (c2_len < 16) {
        *m_len = 0;
        goto done_dem_inverse;
    }

    /* Hash key to obtain final key and IV */
    shake256(final_key_iv, (size_t) (PARAMS_KAPPA_BYTES + 12), key, PARAMS_KAPPA_BYTES);

    /* Get tag */
    copy_u8(tag, c2 + c2_len_no_tag, 16);

    /* Initialise AES GCM */
    res = !(ctx = EVP_CIPHER_CTX_new()) || (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, final_key_iv, iv) != 1);
    if (res) {
    crash_immediately();
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); /* Disable padding */

    /* Decrypt */
    tmp_m = m;
    diff = m - c2;
    if ((diff >= 0 && diff < (ptrdiff_t) c2_len_no_tag) || (diff < 0 && diff > -((ptrdiff_t) c2_len_no_tag))) {
        /* EVP_DecryptUpdate does not handle overlapping pointers so we need
           to create a temporary buffer for the decrypted message. */
    tmp_m = (uint8_t*)malloc(c2_len_no_tag);
    }
    if (EVP_DecryptUpdate(ctx, tmp_m, &len, c2, (int) c2_len_no_tag) != 1) {
        goto done_dem_inverse;
    }
    if (tmp_m != m) {
        /* Copy temporary message to result message, free temp message buffer */
        copy_u8(m, tmp_m, (size_t) len);
        free(tmp_m);
    }
    m_length = len;

    /* Set expected tag value  */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        goto done_dem_inverse;
    }

    /* Finalise decrypt */
    ret = EVP_DecryptFinal_ex(ctx, m + m_length, &len);
    if (ret < 0) {
        goto done_dem_inverse;
    }

    /* Set decrypted message length */
    *m_len = (size_t) m_length;

    /* OK */
    result = 0;

done_dem_inverse:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}


/**
     * Generates an ENCRYPT key pair.
     *
     * @param[out] pk public key
     * @param[out] sk secret key
     * @return __0__ in case of success
     */
int crypto_encrypt_keypair(uint8_t *pk, uint8_t *sk, const uint8_t coins[3*32]) {
return r5_cca_kem_keygen(pk, sk, coins);
    }

    /**
     * Encrypts a message.
     *
     * @param[out] ct     the encrypted message
     * @param[out] ct_len the length of the encrypted message (`CRYPTO_CIPHERTEXTBYTES` + `m_len`)
     * @param[in]  m      the message to encrypt
     * @param[in]  m_len  the length of the message to encrypt
     * @param[in]  pk     the public key to use for the encryption
     * @return __0__ in case of success
     */
int crypto_encrypt(uint8_t *ct, size_t *ct_len, const uint8_t *m, const size_t m_len, const uint8_t *pk, const uint8_t coins[32]) {
    int result = -1;
    const size_t c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;
    uint8_t c1[PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES];
    size_t c2_len;
    uint8_t k[PARAMS_KAPPA_BYTES];

    /* Determine c1 and k */
    r5_cca_kem_encapsulate(c1, k, pk, coins);

    /* Copy c1 into first part of ct */
    copy_u8(ct, c1, c1_len);
    *ct_len = c1_len;

    /* Apply DEM to get second part of ct */
    if (round5_dem(ct + c1_len, &c2_len, k, m, m_len)) {
        goto done_encrypt;
    }
    *ct_len += c2_len;

    /* All OK */
    result = 0;

done_encrypt:

    return result;
    }

    /**
     * Decrypts a message.
     *
     * @param[out] m      the decrypted message
     * @param[out] m_len  the length of the decrypted message (`ct_len` - `CRYPTO_CIPHERTEXTBYTES`)
     * @param[in]  ct     the message to decrypt
     * @param[in]  ct_len the length of the message to decrypt
     * @param[in]  sk     the secret key to use for the decryption
     * @return __0__ in case of success
     */
    int crypto_encrypt_open(uint8_t *m, size_t *m_len, const uint8_t *ct, const size_t ct_len, const uint8_t *sk) {
    int result = -1;
    uint8_t k[PARAMS_KAPPA_BYTES];
    const uint8_t * const c1 = ct;
    const size_t c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;
    const uint8_t * const c2 = ct + c1_len;
    const size_t c2_len = ct_len - c1_len;

    /* Check length, should be at least c1_len + 16 (for the DEM tag) */
    if (ct_len < (c1_len + 16U)) {
        goto done_decrypt;
    }

    /* Determine k */
    r5_cca_kem_decapsulate(k, c1, sk);

    /* Apply DEM-inverse to get m */
    if (round5_dem_inverse(m, m_len, k, c2, c2_len)) {
        goto done_decrypt;
    }

    /* OK */
    result = 0;

done_decrypt:

    return result;
    }
