/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Definition of the hash function as used within Round5.
 */

#ifndef R5_HASH_H
#define R5_HASH_H

#include "shake.h"


    /**
     * The hash function as used within Round5.
     *
     * @param[out] output      buffer for the output of the hash
     * @param[in]  output_len  the number of hash bytes to produce
     * @param[in]  input       the input to produce the hash for
     * @param[in]  input_len   the number of input bytes
     * @param[in]  kappa_bytes the number of bytes of kappa (used to determine
     *                         the implementation of the hash function)
     */
    inline void hash(uint8_t *output, const size_t output_len, const uint8_t *input, const size_t input_len, const uint8_t kappa_bytes) {
        /* Since without customization, SHAKE == CSHAKE, we can use SHAKE here directly. */
        if (kappa_bytes > 16) {
            shake256(output, output_len, input, input_len);
        } else {
            shake128(output, output_len, input, input_len);
        }
    }

#endif /* R5_HASH_H */
