/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the DEM functions used by the Round5 CCA KEM-based encrypt algorithm.
 */

#ifndef PST_DEM_H
#define PST_DEM_H

#include "types.h"

    /**
     * Applies a DEM to the given message using the specified key.
     *
     * @param[out] c2     the encapsulated message
     * @param[out] c2_len the length of the encapsulated message (`m_len` + 16 bytes)
     * @param[in]  key    the key to use for the encapsulation
     * @param[in]  m      the message to encapsulate
     * @param[in]  m_len  the length of the message
     * @return __0__ in case of success
     */
    int round5_dem(uint8_t *c2, size_t *c2_len, const uint8_t *key, const uint8_t *m, const size_t m_len);

    /**
     * Inverses the application of a DEM to a message.
     *
     * @param[out] m       the original message
     * @param[out] m_len   the length of the decapsulated message (`c2_len` - 16)
     * @param[in]  key     the key to use for the encapsulation
     * @param[in]  c2      the encapsulated message
     * @param[in]  c2_len  the length of the encapsulated message
     * @return __0__ in case of success
     */
    int round5_dem_inverse(uint8_t *m, size_t *m_len, const uint8_t *key, const uint8_t *c2, const size_t c2_len);

#endif /* PST_DEM_H */
