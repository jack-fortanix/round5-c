/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the SHAKE128, SHAKE256, cSHAKE128, and cSHAKE256 hash
 * functions.
 *
 * Note: all sizes are in bytes, not bits!
 */

#ifndef _SHAKE_H_
#define _SHAKE_H_

#include "types.h"
#include "utils.h"

typedef uint8_t shake_ctx[224];

/**
 * The rate of the SHAKE-256 algorithm (i.e. internal block size, in bytes).
 */
static const size_t SHAKE256_RATE = 136;

    /**
     * Performs the initialisation step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     */
void shake256_init(shake_ctx *ctx);

    /**
     * Performs the absorb step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     * @param input the input absorbed into the state
     * @param input_len the length of the input
     */
void shake256_absorb(shake_ctx *ctx, const uint8_t *input, const size_t input_len);

    /**
     * Performs the squeeze step of the SHAKE-256 XOF. Squeezes full blocks of
     * SHAKE256_RATE bytes each. Can be called multiple times to keep squeezing
     * (i.e. this function is incremental).
     *
     * @param ctx the shake context
     * @param output the output
     * @param nr_blocks the number of blocks to squeeze
     */
void shake256_squeezeblocks(shake_ctx *ctx, uint8_t *output, const size_t nr_blocks);

    /**
     * Performs the full SHAKE-256 XOF to the given input.
     * @param output the final output
     * @param output_len the length of the output
     * @param input the input
     * @param input_len the length of the input
     */
void shake256(uint8_t *output, size_t output_len, const uint8_t *input, const size_t input_len);

#endif /* SHAKE_H */
