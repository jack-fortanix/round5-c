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

#include <stdlib.h>
#include <stddef.h>
#include "types.h"


extern "C" {
#include <libkeccak.a.headers/KeccakHash.h>
}

typedef Keccak_HashInstance shake_ctx; /**< The shake context (state) */

/**
 * The rate of the SHAKE-256 algorithm (i.e. internal block size, in bytes).
 */
#define SHAKE256_RATE 136

    /**
     * Performs the initialisation step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     */
    inline void shake256_init(shake_ctx *ctx) {
        if (Keccak_HashInitialize_SHAKE256(ctx) != 0) {
            abort();
        }
    }

    /**
     * Performs the absorb step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     * @param input the input absorbed into the state
     * @param input_len the length of the input
     */
    inline void shake256_absorb(shake_ctx *ctx, const uint8_t *input, const size_t input_len) {
        if (Keccak_HashUpdate(ctx, input, input_len * 8) != 0) {
            abort();
        }
        if (Keccak_HashFinal(ctx, NULL) != 0) {
            abort();
        }
    }

    /**
     * Performs the squeeze step of the SHAKE-256 XOF. Squeezes full blocks of
     * SHAKE256_RATE bytes each. Can be called multiple times to keep squeezing
     * (i.e. this function is incremental).
     *
     * @param ctx the shake context
     * @param output the output
     * @param nr_blocks the number of blocks to squeeze
     */
    inline void shake256_squeezeblocks(shake_ctx *ctx, uint8_t *output, const size_t nr_blocks) {
        if (Keccak_HashSqueeze(ctx, output, nr_blocks * SHAKE256_RATE * 8) != 0) {
            abort();
        }
    }

    /**
     * Performs the full SHAKE-256 XOF to the given input.
     * @param output the final output
     * @param output_len the length of the output
     * @param input the input
     * @param input_len the length of the input
     */
    void shake256(uint8_t *output, const size_t output_len, const uint8_t *input, const size_t input_len);

#endif /* SHAKE_H */
