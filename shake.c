#include "shake.h"
#include "utils.h"

extern "C" {
#include <libkeccak.a.headers/KeccakHash.h>
}

//static_assert(sizeof(Keccak_HashInstance) == sizeof(shake_ctx), "Expected size");

    void shake256_init(shake_ctx *ctx) {
        if (Keccak_HashInitialize_SHAKE256((Keccak_HashInstance*)ctx) != 0) {
            crash_immediately();
        }
    }

    /**
     * Performs the absorb step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     * @param input the input absorbed into the state
     * @param input_len the length of the input
     */
    void shake256_absorb(shake_ctx *ctx, const uint8_t *input, const size_t input_len) {
        if (Keccak_HashUpdate((Keccak_HashInstance*)ctx, input, input_len * 8) != 0) {
            crash_immediately();
        }
        if (Keccak_HashFinal((Keccak_HashInstance*)ctx, NULL) != 0) {
            crash_immediately();
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
    void shake256_squeezeblocks(shake_ctx *ctx, uint8_t *output, const size_t nr_blocks) {
        if (Keccak_HashSqueeze((Keccak_HashInstance*)ctx, output, nr_blocks * SHAKE256_RATE * 8) != 0) {
            crash_immediately();
        }
    }

    /**
     * Performs the full SHAKE-256 XOF to the given input.
     * @param output the final output
     * @param output_len the length of the output
     * @param input the input
     * @param input_len the length of the input
     */
    void shake256(uint8_t *output, size_t output_len, const uint8_t *input, const size_t input_len) {
    shake_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, input, input_len);
    if (Keccak_HashSqueeze((Keccak_HashInstance*)&ctx, output, output_len * 8) != 0) {
        crash_immediately();
    }
    }
