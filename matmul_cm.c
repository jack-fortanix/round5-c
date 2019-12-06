/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */



#include "matmul.h"

#if PARAMS_K !=1 && defined(CM_CACHE)

#include <string.h>



#include "drbg.h"
#include "little_endian.h"
#include "probe_cm.h"



// create a sparse ternary vector from a seed

void create_secret_matrix_s_t(int16_t s_t[PARAMS_N_BAR][PARAMS_D], const uint8_t *seed) {
    uint16_t i, h, l;
    
    uint16_t x;
    uint16_t base[PARAMS_H];
    uint16_t *y = &(base[PARAMS_H]);
    
    uint64_t add[2 * PROBEVEC64];
    uint64_t* sub = add + PROBEVEC64;
    
    memset(s_t, 0, PARAMS_N_BAR * PARAMS_D * sizeof (int16_t));
    drbg_init(seed);
    
    for (l = 0; l < PARAMS_N_BAR; l++) {
        memset(add, 0, sizeof (add));
        
        for (h = 0; h < PARAMS_H / 2; h++) {
            do {
                do {
                    if (y == &base[PARAMS_H]) {
                        y = base;
                        drbg(base, sizeof (base));
                    }
                    x = *y++;
                } while (x >= PARAMS_RS_LIM);
            } while (probe_cm(add, sub, x/PARAMS_RS_DIV));
            
            do {
                do {
                    if (y == &base[PARAMS_H]) {
                        y = base;
                        drbg(base, sizeof (base));
                    }
                    x = *y++;
                } while (x >= PARAMS_RS_LIM);
            } while (probe_cm(sub ,add , x/PARAMS_RS_DIV));
        }
        
        for (i = 0; i < PARAMS_D; i++) {
            s_t[l][i] = (int16_t) (((add[i >> 6] >> (i & 0x3F)) & 1)
                                   - ((sub[i >> 6] >> (i & 0x3F)) & 1));
            // this is constant time since it goes through all values and always perform same operation.
        }
    }
}

// create a sparse ternary vector from a seed
void create_secret_matrix_r_t(int16_t r_t[PARAMS_M_BAR][PARAMS_D], const uint8_t *seed) {
    uint16_t i, h, l;
    
    uint16_t x;
    uint16_t base[PARAMS_H];
    uint16_t *y = &(base[PARAMS_H]);
    
    uint64_t add[2 * PROBEVEC64];
    uint64_t* sub = add + PROBEVEC64;
    
    memset(r_t, 0, PARAMS_M_BAR * PARAMS_D * sizeof (int16_t));
    drbg_init(seed);
    
    for (l = 0; l < PARAMS_M_BAR; l++) {
        memset(add, 0, sizeof (add));
        
        for (h = 0; h < PARAMS_H / 2; h++) {
            do {
                do {
                    if (y == &base[PARAMS_H]) {
                        y = base;
                        drbg(base, sizeof (base));
                    }
                    x = *y++;
                } while (x >= PARAMS_RS_LIM);
            } while (probe_cm(add, sub, x/PARAMS_RS_DIV));
            
            do {
                do {
                    if (y == &base[PARAMS_H]) {
                        y = base;
                        drbg(base, sizeof (base));
                    }
                    x = *y++;
                } while (x >= PARAMS_RS_LIM);
            } while (probe_cm(sub ,add , x/PARAMS_RS_DIV));
        }
        
        for (i = 0; i < PARAMS_D; i++) {
            r_t[l][i] = (int16_t) (((add[i >> 6] >> (i & 0x3F)) & 1)
                                   - ((sub[i >> 6] >> (i & 0x3F)) & 1));
            // this is constant time since it goes through all values and always perform same operation.
        }
    }
}

// B = A * S

void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[PARAMS_D][PARAMS_D], int16_t s_t[PARAMS_N_BAR][PARAMS_D]) {

    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_N_BAR * PARAMS_D * sizeof (modq_t));

#define A_element(j, i) a[j][i]
    for (j = 0; j < PARAMS_D; j++) {
        for (l = 0; l < PARAMS_N_BAR; l++) {
            for (i = 0; i < PARAMS_D; i++) {
                d[j][l] = (modq_t) (d[j][l] + s_t[l][i] * A_element(j, i));
            }
        }
    }
}

// U^T = R^T * A

void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t a[PARAMS_D][PARAMS_D], int16_t r_t[PARAMS_M_BAR][PARAMS_D]) {

    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_M_BAR * PARAMS_D * sizeof (modq_t));

#define A_element(i, j) a[i][j]
    for (i = 0; i < PARAMS_D; i++) {
        for (j = 0; j < PARAMS_D; j++) {
            for (l = 0; l < PARAMS_M_BAR; l++) {
                d[l][j] = (modq_t) (d[l][j] + r_t[l][i] * A_element(i, j));
            }
        }
    }
#undef A_element
}

// X' = S^T * U

void matmul_stu_p(modp_t d[PARAMS_MU], modp_t u_t[PARAMS_M_BAR][PARAMS_D], int16_t s_t[PARAMS_N_BAR][PARAMS_D]) {
    size_t i, l, j;

    // Initialize result
    memset(d, 0, PARAMS_MU * sizeof (modp_t));

    size_t index = 0;
    for (l = 0; l < PARAMS_N_BAR && index < PARAMS_MU; ++l) {
        for (j = 0; j < PARAMS_M_BAR && index < PARAMS_MU; ++j) {
            for (i = 0; i < PARAMS_D; ++i) {
                d[index] = (modp_t) (d[index] + s_t[l][i] * u_t[j][i]);
            }
            ++index;
        }
    }
}

// X = B^T * R

void matmul_btr_p(modp_t d[PARAMS_MU], modp_t b[PARAMS_D][PARAMS_N_BAR], int16_t r_t[PARAMS_M_BAR][PARAMS_D]) {
    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_MU * sizeof (modp_t));

    size_t index = 0;
    for (l = 0; l < PARAMS_N_BAR && index < PARAMS_MU; ++l) {
        for (j = 0; j < PARAMS_M_BAR && index < PARAMS_MU; ++j) {
            for (i = 0; i < PARAMS_D; ++i) {
                d[index] = (modp_t) (d[index] + b[i][l] * r_t[j][i]);
            }
            ++index;
        }
    }
}

#endif /* PARAMS_K !=1 && defined(CM_CACHE) */
