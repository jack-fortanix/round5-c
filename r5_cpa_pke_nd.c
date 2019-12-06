/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#include "r5_cpa_pke.h"
#include "r5_parameter_sets.h"
#include "shake.h"
#include "rng.h"
#include "io.h"

#include <stdio.h>

// Size of the vector to pass to probe_cm
#define PROBEVEC64  ((PARAMS_D + 63) / 64)

/**
 * Constant-time 64-bit left shift of 1. Use if platform's left shift with
 * variable amount is constant-time.
 *
 * @param shift_amount the number of bits to shift the value 1 to the left
 * @param flag flag to indicate the shift amount can be >= 32 (ignored)
 * @return 1 << shift_amount
 */
#define constant_time_shift_1_left64(out, shift_amount, flag) out = (1llu << (shift_amount))

// Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
// Return value zero (false) indicates the slot was originally empty.

static int probe_cm(uint64_t *v, const uint16_t x) {
    uint64_t a, b, c, y, z;
    // construct the selector
    constant_time_shift_1_left64(y, x & 0x3F, 1); // low bits of index
    constant_time_shift_1_left64(z, x >> 6, 0); // high bits of index

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

int r5_cpa_pke_keygen(uint8_t *pk, uint8_t *sk) {
    modq_t A[PARAMS_ND];
    modq_t B[PARAMS_ND];
    uint16_t S_idx[PARAMS_H / 2][2];

    randombytes(pk, PARAMS_KAPPA_BYTES); // sigma = seed of A
#ifdef NIST_KAT_GENERATION
    printf("r5_cpa_pke_keygen: tau=%zu\n", PARAMS_TAU);
    print_hex("r5_cpa_pke_keygen: sigma", pk, PARAMS_KAPPA_BYTES, 1);
#endif

    // A from sigma
    create_A_random(A, pk);

    randombytes(sk, PARAMS_KAPPA_BYTES); // secret key -- Random S
    create_secret_vector(S_idx, sk);

    ringmul_q(B, A, S_idx); // B = A * S

    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p(pk + PARAMS_KAPPA_BYTES, B, PARAMS_H1);

    return 0;
}

int r5_cpa_pke_encrypt(uint8_t *ct, const uint8_t *pk, const uint8_t *m, const uint8_t *rho) {
    size_t i, j;
    modq_t A[PARAMS_ND];
    uint16_t R_idx[PARAMS_H / 2][2];
    modq_t U_T[PARAMS_ND];
    modp_t B[PARAMS_ND];
    modp_t X[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)];
    modp_t t, tm;

    // unpack public key
    unpack_p(B, pk + PARAMS_KAPPA_BYTES);

    // A from sigma
    create_A_random(A, pk);

    copy_u8(m1, m, PARAMS_KAPPA_BYTES); // add error correction code
    zero_u8(m1 + PARAMS_KAPPA_BYTES, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS) - PARAMS_KAPPA_BYTES);

    // Create R
    create_secret_vector(R_idx, rho);

    ringmul_q(U_T, A, R_idx); // U^T == U = A^T * R == A * R (mod q)
    ringmul_p(X, B, R_idx); // X = B^T * R == B * R (mod p)

#ifdef NIST_KAT_GENERATION
    print_hex("r5_cpa_pke_encrypt: rho", rho, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cpa_pke_encrypt: sigma", pk, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cpa_pke_encrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
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

int r5_cpa_pke_decrypt(uint8_t *m, const uint8_t *sk, const uint8_t *ct) {
    size_t i, j;
    uint16_t S_idx[PARAMS_H / 2][2];
    modp_t U_T[PARAMS_ND];
    modp_t v[PARAMS_MU];
    modp_t t, X_prime[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)] = { 0 };

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
