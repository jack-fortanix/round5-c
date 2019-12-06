/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#ifndef _R5_PARAMETER_SETS_H_
#define _R5_PARAMETER_SETS_H_

#include "types.h"
#include <stddef.h>
#include "utils.h"

// Parameter Set definitions

/* NIST API Round5 parameter set definition */
#define CM_CACHE

#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 32
#define PARAMS_D           1170
#define PARAMS_N           1170
#define PARAMS_H           222
#define PARAMS_Q_BITS      13
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      5
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_5PKE_0d"

// appropriate types
typedef uint16_t modq_t;
typedef uint16_t modp_t;
typedef uint8_t modt_t;

#define PARAMS_ND       PARAMS_D
#define PARAMS_K        (PARAMS_D/PARAMS_N)
#define PARAMS_Q        (1 << PARAMS_Q_BITS)
#define PARAMS_Q_MASK   (PARAMS_Q - 1)
#define PARAMS_P        (1 << PARAMS_P_BITS)
#define PARAMS_P_MASK   (PARAMS_P - 1)
#define PARAMS_KAPPA    (8 * PARAMS_KAPPA_BYTES)
#define PARAMS_MU       CEIL_DIV((PARAMS_KAPPA + PARAMS_XE), PARAMS_B_BITS)
#define PARAMS_MUT_SIZE BITS_TO_BYTES(PARAMS_MU * PARAMS_T_BITS)

#define PARAMS_RS_DIV   (0x10000 / PARAMS_ND)
#define PARAMS_RS_LIM   (PARAMS_ND * PARAMS_RS_DIV)
#define PARAMS_NDP_SIZE BITS_TO_BYTES(PARAMS_ND * PARAMS_P_BITS)

// Definition of TAU parameter, defaults to 0 unless otherwise defined and non-ring
#if PARAMS_K == 1 || !defined(ROUND5_API_TAU)
#undef ROUND5_API_TAU
#define ROUND5_API_TAU 0
#endif
#define PARAMS_TAU      ROUND5_API_TAU

// Define the length of the random vector when TAU is 2 is used for generating A, defaults to parameter 2^11.
// Important: Must be a power of two and > d
#if !defined(ROUND5_API_TAU2_LEN) || ROUND5_API_TAU2_LEN == 0
#undef ROUND5_API_TAU2_LEN
#define ROUND5_API_TAU2_LEN (1<<11)
#endif
#if ROUND5_API_TAU2_LEN > (1<<31)
#error ROUND5_API_TAU2_LEN must be less than or equal to 2^31
#endif
#if (ROUND5_API_TAU2_LEN & (ROUND5_API_TAU2_LEN - 1)) != 0 || ROUND5_API_TAU2_LEN < PARAMS_D
#error ROUND5_API_TAU2_LEN must be a power of two and greater than or equal to PARAMS_D
#endif
#define PARAMS_TAU2_LEN ROUND5_API_TAU2_LEN

// Rounding constants
#if ((PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS) < PARAMS_P_BITS)
#define PARAMS_Z_BITS   PARAMS_P_BITS
#else
#define PARAMS_Z_BITS   (PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS)
#endif
#define PARAMS_H1       (1 << (PARAMS_Q_BITS - PARAMS_P_BITS - 1))
#define PARAMS_H2       (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1))
#define PARAMS_H3       ((1 << (PARAMS_P_BITS - PARAMS_T_BITS - 1)) + (1 << (PARAMS_P_BITS - PARAMS_B_BITS - 1)) - (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1)))

#if PARAMS_K == 1
#define PARAMS_PK_SIZE  (PARAMS_KAPPA_BYTES + PARAMS_NDP_SIZE)
#define PARAMS_CT_SIZE  (PARAMS_NDP_SIZE + PARAMS_MUT_SIZE)
#else
#error bad k

#define PARAMS_PK_SIZE  (PARAMS_KAPPA_BYTES + PARAMS_DP_SIZE)
#define PARAMS_CT_SIZE  (PARAMS_DPU_SIZE + PARAMS_MUT_SIZE)

// Packing shift
#if PARAMS_B_BITS == 1
#define PACK_SHIFT 3
#define PACK_AND 7
#endif
#if PARAMS_B_BITS == 2
#define PACK_SHIFT 2
#define PACK_AND 3
#endif
#if PARAMS_B_BITS == 4
#define PACK_SHIFT 1
#define PACK_AND 1
#endif

#endif

// CCA_PKE Variant
#define CRYPTO_SECRETKEYBYTES  (PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE)
#define CRYPTO_PUBLICKEYBYTES  PARAMS_PK_SIZE
#define CRYPTO_BYTES           (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + 16)
#define CRYPTO_CIPHERTEXTBYTES 0

#if PARAMS_TAU != 0
 #error "bad tau"
#endif

// AVX2 implies CM_CACHE
#define CM_CACHE

#endif /* _R5_PARAMETER_SETS_H_ */
