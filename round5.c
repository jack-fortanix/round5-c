
#include "round5.h"
#include "r5_parameter_sets.h"
#include "shake.h"
#include "utils.h"
#include "io.h"
#include <openssl/evp.h>

// Size of the vector to pass to probe_cm
static const size_t PROBEVEC64 =  ((PARAMS_D + 63) / 64);

// Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
// Return value zero (false) indicates the slot was originally empty.

static int probe_cm(uint64_t *v, const uint16_t x) {
    uint64_t a, b, c;
    // construct the selector

    uint64_t y = (1ULL) << (x & 0x3F);
    uint64_t z = (1ULL) << (x >> 6);

    c = 0;
    for (size_t i = 0; i < PROBEVEC64; i++) { // always scan through all
        a = v[i];
        b = a | (y & (-(z & 1))); // set bit if not occupied.
        c |= a ^ b; // If change, mask.
        v[i] = b; // update value of v[i]
        z >>= 1;
    }
    // final comparison doesn't need to be constant time
    return c == 0; // return true if was occupied before
}

// create a sparse ternary vector from a seed

static void create_secret_vector(uint16_t idx[PARAMS_H / 2][2], const uint8_t seed[PARAMS_KAPPA_BYTES]) {
    uint64_t v[PROBEVEC64] = { 0 };

    shake_ctx shake;

    shake256_init(&shake);
    shake256_absorb(&shake, seed, PARAMS_KAPPA_BYTES);
    size_t index = SHAKE256_RATE;
    uint8_t output[SHAKE256_RATE] = { 0 };

    for (size_t i = 0; i < PARAMS_H; i++) {
        uint16_t x;
        do {
            do {

            for (size_t j = 0; j < 2; j++) {
                if (index >= SHAKE256_RATE) {
                    shake256_squeezeblocks(&shake, output, 1);
                    index = 0;
                }

                ((uint8_t *) &x)[j] = output[index++];
            }

            } while (x >= PARAMS_RS_LIM);
            x /= PARAMS_RS_DIV;
        } while (probe_cm(v, x));
        idx[i >> 1][i & 1] = x; // addition / subtract index
    }
}

// multiplication mod q, result length n

static void ringmul_q(modq_t d[PARAMS_ND], modq_t a[PARAMS_ND], uint16_t idx[PARAMS_H / 2][2]) {
    size_t i, j, k;
    modq_t p[PARAMS_ND + 1];

    // Note: order of coefficients a[1..n] is reversed!
    // "lift" -- multiply by (x - 1)
    p[0] = (modq_t) (-a[0]);
    for (i = 1; i < PARAMS_ND; i++) {
        p[PARAMS_ND + 1 - i] = (modq_t) (a[i - 1] - a[i]);
    }
    p[1] = a[PARAMS_ND - 1];

    // Initialize result
    zero_u16(d, PARAMS_ND);

    for (i = 0; i < PARAMS_H / 2; i++) {
        // Modified to always scan the same ranges

        k = idx[i][0]; // positive coefficients
        d[0] = (modq_t) (d[0] + p[k]);
        for (j = 1; k > 0;) {
            d[j] = (modq_t) (d[j] + p[--k]);
            j++;
        }
        for (k = PARAMS_ND + 1; j < PARAMS_ND;) {
            d[j] = (modq_t) (d[j] + p[--k]);
            j++;
        }

        k = idx[i][1]; // negative coefficients
        d[0] = (modq_t) (d[0] - p[k]);
        for (j = 1; k > 0;) {
            d[j] = (modq_t) (d[j] - p[--k]);
            j++;
        }
        for (k = PARAMS_ND + 1; j < PARAMS_ND;) {
            d[j] = (modq_t) (d[j] - p[--k]);
            j++;
        }
    }

    // "unlift"
    d[0] = (uint16_t) (-d[0]);
    for (i = 1; i < PARAMS_ND; ++i) {
        d[i] = (uint16_t) (d[i - 1] - d[i]);
    }
}

// multiplication mod p, result length mu

static void ringmul_p(modp_t d[PARAMS_MU], modp_t a[PARAMS_ND], uint16_t idx[PARAMS_H / 2][2]) {
    size_t i, j, k;
    modp_t p[PARAMS_ND + 1];

    // Note: order of coefficients a[1..n] is reversed!
    // Without error correction we "lift" -- i.e. multiply by (x - 1)
    p[0] = (modp_t) (-a[0]);
    for (i = 1; i < PARAMS_ND; i++) {
        p[PARAMS_ND + 1 - i] = (modp_t) (a[i - 1] - a[i]);
    }
    p[1] = a[PARAMS_ND - 1];

    // Initialize result
    modp_t tmp_d[PARAMS_ND] = { 0 };

    for (i = 0; i < PARAMS_H / 2; i++) {
        // Modified to always scan the same ranges

        k = idx[i][0]; // positive coefficients
        tmp_d[0] = (modp_t) (tmp_d[0] + p[k]);
        for (j = 1; k > 0;) {
            tmp_d[j] = (modp_t) (tmp_d[j] + p[--k]);
            j++;
        }
        for (k = PARAMS_ND + 1; j < PARAMS_ND;) {
            tmp_d[j] = (modp_t) (tmp_d[j] + p[--k]);
            j++;
        }

        k = idx[i][1]; // negative coefficients
        tmp_d[0] = (modp_t) (tmp_d[0] - p[k]);
        for (j = 1; k > 0;) {
            tmp_d[j] = (modp_t) (tmp_d[j] - p[--k]);
            j++;
        }
        for (k = PARAMS_ND + 1; j < PARAMS_ND;) {
            tmp_d[j] = (modp_t) (tmp_d[j] - p[--k]);
            j++;
        }
    }

    // Without error correction we "lifted" so we now need to "unlift"
    tmp_d[0] = (modp_t) (-tmp_d[0]);
    for (i = 1; i < PARAMS_MU; ++i) {
        tmp_d[i] = (modp_t) (tmp_d[i - 1] - tmp_d[i]);
    }
    // Copy result
    copy_u16(d, tmp_d, PARAMS_MU);
}

// Creates A random for the given seed and algorithm parameters.
static void create_A_random(modq_t *A_random, const uint8_t *seed) {
   shake256((uint8_t *)A_random, (PARAMS_D*PARAMS_K) * sizeof (uint16_t), seed, PARAMS_KAPPA_BYTES);
}

// compress ND elements of q bits into p bits and pack into a byte string

static void pack_q_p(uint8_t *pv, const modq_t *vq, const modq_t rounding_constant) {
    size_t i, j;
    modp_t t;

    zero_u8(pv, PARAMS_NDP_SIZE);
    j = 0;
    for (i = 0; i < PARAMS_ND; i++) {
        t = ((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1);
        pv[j >> 3] = (uint8_t) (pv[j >> 3] | (t << (j & 7))); // pack p bits
        if ((j & 7) + PARAMS_P_BITS > 8) {
            pv[(j >> 3) + 1] = (uint8_t) (pv[(j >> 3) + 1] | (t >> (8 - (j & 7))));
        }
        j += PARAMS_P_BITS;
    }
}

// unpack a byte string into ND elements of p bits

static void unpack_p(modp_t *vp, const uint8_t *pv) {
    size_t i, j;
    modp_t t;

    j = 0;
    for (i = 0; i < PARAMS_ND; i++) {
        t = (modp_t) (pv[j >> 3] >> (j & 7)); // unpack p bits
        if ((j & 7) + PARAMS_P_BITS > 8) {
            t = (modp_t) (t | ((modp_t) pv[(j >> 3) + 1]) << (8 - (j & 7)));
        }
        vp[i] = t & (PARAMS_P - 1);
        j += PARAMS_P_BITS;
    }
}

// generate a keypair (sigma, B)

static int r5_cpa_pke_keygen(uint8_t *pk, uint8_t *sk, const uint8_t seed[64]) {
    modq_t A[PARAMS_ND];
    modq_t B[PARAMS_ND];
    uint16_t S_idx[PARAMS_H / 2][2];

    copy_u8(pk, seed, 32); // sigma = seed of A
#ifdef NIST_KAT_GENERATION
    print_hex("r5_cpa_pke_keygen: sigma", pk, PARAMS_KAPPA_BYTES, 1);
#endif

    // A from sigma
    create_A_random(A, pk);

    copy_u8(sk, seed + 32, 32); // secret key -- Random S
    create_secret_vector(S_idx, sk);

    ringmul_q(B, A, S_idx); // B = A * S

    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p(pk + PARAMS_KAPPA_BYTES, B, PARAMS_H1);

    return 0;
}

static int r5_cpa_pke_encrypt(uint8_t *ct, const uint8_t *pk, const uint8_t *m, const uint8_t *rho) {
    size_t i, j;
    modq_t A[PARAMS_ND];
    uint16_t R_idx[PARAMS_H / 2][2];
    modq_t U_T[PARAMS_ND];
    modp_t B[PARAMS_ND];
    modp_t X[PARAMS_MU];
    uint8_t m1[PARAMS_MUB_SIZE];
    modp_t t, tm;

    // unpack public key
    unpack_p(B, pk + PARAMS_KAPPA_BYTES);

    // A from sigma
    create_A_random(A, pk);

    copy_u8(m1, m, PARAMS_KAPPA_BYTES); // add error correction code
    zero_u8(m1 + PARAMS_KAPPA_BYTES, PARAMS_MUB_SIZE - PARAMS_KAPPA_BYTES);

    // Create R
    create_secret_vector(R_idx, rho);

    ringmul_q(U_T, A, R_idx); // U^T == U = A^T * R == A * R (mod q)
    ringmul_p(X, B, R_idx); // X = B^T * R == B * R (mod p)

#ifdef NIST_KAT_GENERATION
    print_hex("r5_cpa_pke_encrypt: rho", rho, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cpa_pke_encrypt: sigma", pk, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cpa_pke_encrypt: m1", m1, PARAMS_MUB_SIZE, 1);
#endif

    pack_q_p(ct, U_T, PARAMS_H2); // ct = U^T | v

    zero_u8(ct + PARAMS_NDP_SIZE, PARAMS_MUT_SIZE);
    j = 8 * PARAMS_NDP_SIZE;

    for (i = 0; i < PARAMS_MU; i++) { // compute, pack v
        // compress p->t
        t = (modp_t) ((X[i] + PARAMS_H2) >> (PARAMS_P_BITS - PARAMS_T_BITS));
        // add message
        tm = (modp_t) (m1[(i * PARAMS_B_BITS) >> 3] >> ((i * PARAMS_B_BITS) & 7));
        t = (modp_t) (t + ((tm & ((1 << PARAMS_B_BITS) - 1)) << (PARAMS_T_BITS - PARAMS_B_BITS))) & ((1 << PARAMS_T_BITS) - 1);

        ct[j >> 3] = (uint8_t) (ct[j >> 3] | (t << (j & 7))); // pack t bits
        if ((j & 7) + PARAMS_T_BITS > 8) {
            ct[(j >> 3) + 1] = (uint8_t) (ct[(j >> 3) + 1] | (t >> (8 - (j & 7))));
        }
        j += PARAMS_T_BITS;
    }

    return 0;
}

static int r5_cpa_pke_decrypt(uint8_t *m, const uint8_t *sk, const uint8_t *ct) {
    size_t i, j;
    uint16_t S_idx[PARAMS_H / 2][2];
    modp_t U_T[PARAMS_ND];
    modp_t v[PARAMS_MU];
    modp_t t, X_prime[PARAMS_MU];
    uint8_t m1[PARAMS_MUB_SIZE] = { 0 };

    create_secret_vector(S_idx, sk);

    unpack_p(U_T, ct); // ct = U^T | v

    j = 8 * PARAMS_NDP_SIZE;
    for (i = 0; i < PARAMS_MU; i++) {
        t = (modp_t) (ct[j >> 3] >> (j & 7)); // unpack t bits
        if ((j & 7) + PARAMS_T_BITS > 8) {
            t = (modp_t) (t | ct[(j >> 3) + 1] << (8 - (j & 7)));
        }
        v[i] = t & ((1 << PARAMS_T_BITS) - 1);
        j += PARAMS_T_BITS;
    }


    ringmul_p(X_prime, U_T, S_idx); // X' = S^T * U == U^T * S (mod p)


    // X' = v - X', compressed to 1 bit
    modp_t x_p;
    for (i = 0; i < PARAMS_MU; i++) {
        // v - X' as mod p value (to be able to perform the rounding!)
        x_p = (modp_t) ((v[i] << (PARAMS_P_BITS - PARAMS_T_BITS)) - X_prime[i]);
        x_p = (modp_t) (((x_p + PARAMS_H3) >> (PARAMS_P_BITS - PARAMS_B_BITS)) & ((1 << PARAMS_B_BITS) - 1));
        m1[i * PARAMS_B_BITS >> 3] = (uint8_t) (m1[i * PARAMS_B_BITS >> 3] | (x_p << ((i * PARAMS_B_BITS) & 7)));
    }


    copy_u8(m, m1, PARAMS_KAPPA_BYTES);

#ifdef NIST_KAT_GENERATION
    print_hex("r5_cpa_pke_decrypt: m", m, PARAMS_KAPPA_BYTES, 1);
#endif

    return 0;
}

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
        goto done_dem_inverse;
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
