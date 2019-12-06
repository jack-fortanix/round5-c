/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the deterministic random bits (bytes) functions.
 *
 * Uses cSHAKE128 (seed size <= 16 bytes) or cSHAKE256 (seed size > 16 bytes) to
 * generate the random bytes. Unless USE_AES_DRBG is defined, in which case AES
 * in CTR mode on a zero input block with the seed as key is used to generate
 * the random data.
 *
 * Note: in case there is no customization, we use SHAKE directly instead of
 * cSHAKE since this saves some overhead.
 */

#include "drbg.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int drbg_sampler16_2_once(uint16_t *x, const size_t xlen, const void *seed) {
    /* Since without customization, SHAKE == CSHAKE, we use SHAKE here directly. */

shake256((uint8_t *) x, xlen * sizeof (uint16_t), (const uint8_t *) seed, PARAMS_KAPPA_BYTES);

    return 0;
}

