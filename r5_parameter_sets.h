/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#ifndef _R5_PARAMETER_SETS_H_
#define _R5_PARAMETER_SETS_H_

#include "types.h"

// Parameter Set definitions

/* NIST API Round5 parameter set definition */

static const size_t PARAMS_KAPPA_BYTES = 32;
static const size_t PARAMS_D         = 1170;
static const size_t PARAMS_N         = 1170;
static const size_t PARAMS_H         = 222;
static const size_t PARAMS_Q_BITS    = 13;
static const size_t PARAMS_P_BITS    = 9;
static const size_t PARAMS_T_BITS    = 5;
static const size_t PARAMS_B_BITS    = 1;
static const size_t PARAMS_N_BAR     = 1;
static const size_t PARAMS_M_BAR     = 1;
static const size_t PARAMS_F         = 0;

static const size_t PARAMS_ND     = PARAMS_D;
static const size_t PARAMS_K      = (PARAMS_D/PARAMS_N);
static const size_t PARAMS_Q      = (1 << PARAMS_Q_BITS);
static const size_t PARAMS_Q_MASK = (PARAMS_Q - 1);
static const size_t PARAMS_P      = (1 << PARAMS_P_BITS);
static const size_t PARAMS_P_MASK = (PARAMS_P - 1);
static const size_t PARAMS_KAPPA  = (8 * PARAMS_KAPPA_BYTES);
static const size_t PARAMS_MU     = PARAMS_KAPPA;
static const size_t PARAMS_MUT_SIZE = (PARAMS_MU * PARAMS_T_BITS + 7) / 8;

static const size_t PARAMS_RS_DIV = (0x10000 / PARAMS_ND);
static const size_t PARAMS_RS_LIM = (PARAMS_ND * PARAMS_RS_DIV);
static const size_t PARAMS_NDP_SIZE = (PARAMS_ND * PARAMS_P_BITS + 7) / 8;

static const size_t PARAMS_MUB_SIZE = (PARAMS_MU * PARAMS_B_BITS + 7) / 8;

static const size_t PARAMS_TAU = 0;

// Rounding constants
static const size_t PARAMS_Z_BITS = (PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS);
static const size_t PARAMS_H1     = (1 << (PARAMS_Q_BITS - PARAMS_P_BITS - 1));
static const size_t PARAMS_H2     = (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1));
static const size_t PARAMS_H3     = ((1 << (PARAMS_P_BITS - PARAMS_T_BITS - 1)) + (1 << (PARAMS_P_BITS - PARAMS_B_BITS - 1)) - (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1)));

static const size_t PARAMS_PK_SIZE = (PARAMS_KAPPA_BYTES + PARAMS_NDP_SIZE);
static const size_t PARAMS_CT_SIZE = (PARAMS_NDP_SIZE + PARAMS_MUT_SIZE);

// CCA_PKE Variant
static const size_t CRYPTO_SECRETKEYBYTES = (PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);
static const size_t CRYPTO_PUBLICKEYBYTES = PARAMS_PK_SIZE;
static const size_t CRYPTO_BYTES          = (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + 16);

#endif /* _R5_PARAMETER_SETS_H_ */
