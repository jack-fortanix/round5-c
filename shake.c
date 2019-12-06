/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the SHAKE128, SHAKE256, cSHAKE128, and cSHAKE256 hash
 * functions.
 */

#include "shake.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

extern void shake128_init(shake_ctx *ctx);
extern void shake128_absorb(shake_ctx *ctx, const unsigned char *input, const size_t input_len);
extern void shake128_squeezeblocks(shake_ctx *ctx, unsigned char *output, const size_t nr_blocks);

void shake128(unsigned char *output, size_t output_len, const unsigned char *input, const size_t input_len) {
    shake_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, input, input_len);
    if (Keccak_HashSqueeze(&ctx, output, output_len * 8) != 0) {
        abort();
    }
}

extern void shake256_init(shake_ctx *ctx);
extern void shake256_absorb(shake_ctx *ctx, const unsigned char *input, const size_t input_len);
extern void shake256_squeezeblocks(shake_ctx *ctx, unsigned char *output, const size_t nr_blocks);

void shake256(unsigned char *output, size_t output_len, const unsigned char *input, const size_t input_len) {
    shake_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, input, input_len);
    if (Keccak_HashSqueeze(&ctx, output, output_len * 8) != 0) {
        abort();
    }
}
