/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

// Fast ring arithmetic (with cache attack countermeasures)

#include "ringmul.h"
#include "shake.h"

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
    int i;
    uint64_t a, b, c, y, z;
    // construct the selector
    constant_time_shift_1_left64(y, x & 0x3F, 1); // low bits of index
    constant_time_shift_1_left64(z, x >> 6, 0); // high bits of index
    
    c = 0;
    for (i = 0; i < PROBEVEC64; i++) { // always scan through all
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

void create_secret_vector(uint16_t idx[PARAMS_H / 2][2], const uint8_t seed[PARAMS_KAPPA_BYTES]) {
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

void ringmul_q(modq_t d[PARAMS_ND], modq_t a[PARAMS_ND], uint16_t idx[PARAMS_H / 2][2]) {
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

void ringmul_p(modp_t d[PARAMS_MU], modp_t a[PARAMS_ND], uint16_t idx[PARAMS_H / 2][2]) {
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
