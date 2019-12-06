/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#include "r5_parameter_sets.h"

#include "probe_cm.h"

/**
 * Constant-time 64-bit left shift of 1. Use if platform's left shift with
 * variable amount is constant-time.
 *
 * @param shift_amount the number of bits to shift the value 1 to the left
 * @param flag flag to indicate the shift amount can be >= 32 (ignored)
 * @return 1 << shift_amount
 */
#define constant_time_shift_1_left64(out, shift_amount, flag) out = (1llu << (shift_amount))

// Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
// Return value zero (false) indicates the slot was originally empty.

int probe_cm(uint64_t *v, const uint16_t x) {
    int i;
    uint64_t a, b, c, y, z;
    // construct the selector
    constant_time_shift_1_left64(y, x & 0x3F, 1); // low bits of index
    constant_time_shift_1_left64(z, x >> 6, 0); // high bits of index
    
    c = 0;
    for (i = 0; i < PROBEVEC64; i++) { // always scan through all
        a = v[i];
        b = a | (y & (-(z & 1))); // set bit if not occupied.
        c |= a ^ b; // If change, mask.
        v[i] = b; // update value of v[i]
        z >>= 1;
    }
    // final comparison doesn't need to be constant time
    return c == 0; // return true if was occupied before
}
