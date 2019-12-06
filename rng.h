/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the random bytes functions.
 */

#ifndef RNG_H
#define RNG_H

#include "types.h"

    /**
     * Initializes the random number generator used for generating the random
     * bytes.
     *
     * @param[in] entropy_input the bytes to use as input entropy (48 bytes)
     * @param[in] personalization_string an optional personalization string (48 bytes)
     * @param[in] security_strength parameter to specify the security strength of the random bytes
     */
    void randombytes_init(uint8_t *entropy_input, uint8_t *personalization_string, int security_strength);

    /**
     * Generates a sequence of random bytes.
     *
     * @param[out] x destination of the random bytes
     * @param[in] xlen the number of random bytes
     * @return _0_ in case of success, non-zero otherwise
     */
    int randombytes(uint8_t *x, size_t xlen);


#endif /* RNG_H */
