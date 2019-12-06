/*
 * Copyright (c) 2019, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#ifndef PROBE_CM_H
#define PROBE_CM_H

#include "r5_parameter_sets.h"

// Size of the vector to pass to probe_cm
#define PROBEVEC64  ((PARAMS_D + 63) / 64)

    // Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
    // Return value zero (false) indicates the slot was originally empty.

    int probe_cm(uint64_t *v, const uint16_t x);


#endif /* PROBE_CM_H */
