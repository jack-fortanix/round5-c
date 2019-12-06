/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the deterministic random bits (bytes) functions.
 */

#ifndef DRBG_H
#define DRBG_H

#include "r5_parameter_sets.h"
#include "utils.h"
#include "shake.h"
#include "r5_hash.h"

#include <stdint.h>
#include <stddef.h>

/**
 * The DRBG context data structure.
 */
typedef struct drbg_ctx {

    union {
        shake_ctx shake; /**< Context in case of a SHAKE generator */
        cshake_ctx cshake; /**< Context in case of a cSHAKE generator */
    } generator_ctx; /**< The generator context */
    uint8_t output[SHAKE128_RATE > SHAKE256_RATE ? SHAKE128_RATE : SHAKE256_RATE]; /**< Buffer for output. */
    size_t index; /**< Current index in buffer. */
} drbg_ctx;

/**
 * Initializes the deterministic random number generator.
 *
 * @param[in] seed      the seed to use for the deterministic number generator
 */
#define drbg_init(seed) \
    drbg_ctx ctx; \
    shake256_init(&ctx.generator_ctx.shake); \
    shake256_absorb(&ctx.generator_ctx.shake, seed, PARAMS_KAPPA_BYTES); \
    ctx.index = SHAKE256_RATE

/**
 * Initializes the deterministic random number generator with the specified
 * customization string.
 *
 * @param[in] seed              the seed to use for the deterministic number generator
 * @param[in] customization     the customization string to use
 * @param[in] customization_len the length of the customization string
 */
#define drbg_init_customization(seed, customization, customization_len) \
    drbg_ctx ctx; \
    cshake256_init(&ctx.generator_ctx.cshake, customization, customization_len); \
    cshake256_absorb(&ctx.generator_ctx.cshake, seed, PARAMS_KAPPA_BYTES); \
    ctx.index = SHAKE256_RATE

/**
 * Generates the next sequence of deterministic random bytes using the
 * (initial) seed as set with `drbg_init()`.
 *
 * @param[out] x    destination buffer for the random bytes
 * @param[in]  xlen the number of deterministic random bytes to generate
 */

#define drbg(x, xlen) do { \
    size_t i, j; \
    i = ctx.index; \
    for (j = 0; j < xlen; j++) { \
        if (i >= SHAKE256_RATE) { \
            shake256_squeezeblocks(&ctx.generator_ctx.shake, ctx.output, 1); \
            i = 0; \
        } \
        ((uint8_t *) x)[j] = ctx.output[i++]; \
    } \
    ctx.index = i; \
} while (0)

/**
 * Generates the next deterministic random 16-bit integer using the
 * (initial) seed as set with `drbg_init()`.
 *
 * @param[out] x    destination variable for the 16-bit integer
 */
#define drbg16(x) do { \
    drbg(&x, 2); \
    x = (uint16_t) LITTLE_ENDIAN16(x); \
} while (0)

/**
 * Generates the next sequence of deterministic random bytes using the
 * (initial) seed as set with `drbg_init_customization()`.
 *
 * @param[out] x    destination of the random bytes
 * @param[in]  xlen the number of deterministic random bytes to generate
 * @return __0__ in case of success
 */
#define drbg_customization(x, xlen) do { \
    size_t i, j; \
    i = ctx.index; \
    for (j = 0; j < xlen; j++) { \
        if (i >= SHAKE256_RATE) { \
            cshake256_squeezeblocks(&ctx.generator_ctx.cshake, ctx.output, 1); \
            i = 0; \
        } \
        ((uint8_t *) x)[j] = ctx.output[i++]; \
    } \
    ctx.index = i; \
} while (0)

/**
 * Generates the next deterministic random 16-bit integer using the
 * (initial) seed as set with `drbg_init_customization()`.
 *
 * @param[out] x    destination variable for the 16-bit integer
 */
#define drbg16_customization(x) do { \
    drbg_customization(&x, 2); \
    x = (uint16_t) LITTLE_ENDIAN16(x); \
} while (0)

    /**
     * Generates a sequence of deterministic random numbers using the given seed.
     * Can only be used to generate a single sequence of random numbers from the
     * given seed.
     *
     * Use this function to generate a fixed number of deterministic numbers
     * from a seed. It is faster than calling `drbg_init()` and
     * `drbg16()` separately.
     *
     * @param[out] x         destination of the random numbers
     * @param[in]  xlen      the number of deterministic random numbers to generate
     * @param[in]  seed      the seed to use for the deterministic number generator
     * @return __0__ in case of success
     */
    int drbg_sampler16_2_once(uint16_t *x, const size_t xlen, const void *seed);

#endif /* DRBG_H */
