
#include "api.h"
#include "r5_parameter_sets.h"
#include "r5_cpa_pke.h"
#include "shake.h"
#include "io.h"
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


int crypto_encrypt_keypair(uint8_t *pk, uint8_t *sk, const uint8_t coins[3*32]) {
    /* Generate the base key pair */
    r5_cpa_pke_keygen(pk, sk, coins);

    /* Append y and pk to sk */
    copy_u8(sk + PARAMS_KAPPA_BYTES, &coins[64], PARAMS_KAPPA_BYTES);
    copy_u8(sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);

    return 0;
    }

static int r5_cca_kem_encapsulate(uint8_t *ct, uint8_t *k, const uint8_t *pk, const uint8_t coins[32]) {
    uint8_t hash_in[PARAMS_KAPPA_BYTES + (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES > PARAMS_PK_SIZE ? PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES : PARAMS_PK_SIZE)];
    uint8_t L_g_rho[3][PARAMS_KAPPA_BYTES];

    copy_u8(hash_in, coins, PARAMS_KAPPA_BYTES); // G: (l | g | rho) = h(coins | pk);
    copy_u8(hash_in + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);

    shake256((uint8_t *) L_g_rho, 3 * PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);

#ifdef NIST_KAT_GENERATION
    print_hex("r5_cca_kem_encapsulate: m", coins, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_encapsulate: L", L_g_rho[0], PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_encapsulate: g", L_g_rho[1], PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_encapsulate: rho", L_g_rho[2], PARAMS_KAPPA_BYTES, 1);
#endif

    /* Encrypt  */
    r5_cpa_pke_encrypt(ct, pk, coins, L_g_rho[2]); // m: ct = (U,v)

    /* Append g: ct = (U,v,g) */
    copy_u8(ct + PARAMS_CT_SIZE, L_g_rho[1], PARAMS_KAPPA_BYTES);

    /* k = H(L, ct) */
    copy_u8(hash_in, L_g_rho[0], PARAMS_KAPPA_BYTES);
    copy_u8(hash_in + PARAMS_KAPPA_BYTES,
            ct, PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    shake256(k, PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);

    return 0;
}

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

static int r5_cca_kem_decapsulate(uint8_t *k, const uint8_t *ct, const uint8_t *sk) {
    uint8_t hash_in[PARAMS_KAPPA_BYTES + (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES > PARAMS_PK_SIZE ? PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES : PARAMS_PK_SIZE)];
    uint8_t m_prime[PARAMS_KAPPA_BYTES];
    uint8_t L_g_rho_prime[3][PARAMS_KAPPA_BYTES];
    uint8_t ct_prime[PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES];

    r5_cpa_pke_decrypt(m_prime, sk, ct); // r5_cpa_pke_decrypt m'

    copy_u8(hash_in, m_prime, PARAMS_KAPPA_BYTES);
    copy_u8(hash_in + PARAMS_KAPPA_BYTES, // (L | g | rho) = h(m | pk)
            sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, PARAMS_PK_SIZE);
    shake256((uint8_t *) L_g_rho_prime, 3 * PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);

#ifdef NIST_KAT_GENERATION
    print_hex("r5_cca_kem_decapsulate: m_prime", m_prime, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_decapsulate: L_prime", L_g_rho_prime[0], PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_decapsulate: g_prime", L_g_rho_prime[1], PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_decapsulate: rho_prime", L_g_rho_prime[2], PARAMS_KAPPA_BYTES, 1);
#endif

    // Encrypt m: ct' = (U',v')
    r5_cpa_pke_encrypt(ct_prime, sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, m_prime, L_g_rho_prime[2]);

    // ct' = (U',v',g')
    copy_u8(ct_prime + PARAMS_CT_SIZE, L_g_rho_prime[1], PARAMS_KAPPA_BYTES);

    // k = H(L', ct')
    copy_u8(hash_in, L_g_rho_prime[0], PARAMS_KAPPA_BYTES);
    // verification ok ?
    const uint8_t fail = (uint8_t) constant_time_memcmp(ct, ct_prime, PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    // k = H(y, ct') depending on fail state
    conditional_constant_time_memcpy(hash_in, sk + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES, fail);

    copy_u8(hash_in + PARAMS_KAPPA_BYTES, ct_prime, PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    shake256(k, PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);

    return 0;
}

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
