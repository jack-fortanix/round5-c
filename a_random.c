/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the random A matrix creation function.
 */

#include "a_random.h"
#include "shake.h"

void create_A_random(modq_t *A_random, const unsigned char *seed) {
   shake256((uint8_t *)A_random, (PARAMS_D*PARAMS_K) * sizeof (uint16_t), seed, PARAMS_KAPPA_BYTES);
}
