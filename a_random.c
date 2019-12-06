/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the random A matrix creation function.
 */

#include "a_random.h"
#include "drbg.h"

void create_A_random(modq_t *A_random, const unsigned char *seed) {
    drbg_sampler16_2_once(A_random, PARAMS_D * PARAMS_K, seed);
}
