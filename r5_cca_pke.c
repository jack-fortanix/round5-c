/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the encrypt and decrypt functions based on the CCA KEM.
 * algorithm.
 */

#include "r5_cca_pke.h"
#include "r5_parameter_sets.h"
#include "r5_cca_kem.h"
#include "r5_dem.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int r5_cca_pke_keygen(uint8_t *pk, uint8_t *sk, const uint8_t coins[3*32]) {
return r5_cca_kem_keygen(pk, sk, coins);
}

int r5_cca_pke_encrypt(uint8_t *ct, size_t *ct_len, const uint8_t *m, const size_t m_len, const uint8_t *pk, const uint8_t coins[32]) {
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

int r5_cca_pke_decrypt(uint8_t *m, size_t *m_len, const uint8_t *ct, size_t ct_len, const uint8_t *sk) {
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
