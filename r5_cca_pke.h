/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the encrypt and decrypt functions based on the CCA KEM
 * algorithm.
 */

#ifndef _R5_CCA_PKE_H_
#define _R5_CCA_PKE_H_

#include "types.h"

    /**
     * Generates an ENCRYPT key pair. Uses the parameters as specified.
     *
     * @param[out] pk     public key
     * @param[out] sk     secret key (<b>important:</b> the size of `sk` is `sk_size` + `kappa_bytes` + `pk_size`!)
     * @return __0__ in case of success
     */
int r5_cca_pke_keygen(uint8_t *pk, uint8_t *sk, const uint8_t coins[3*32]);

    /**
     * Encrypts a message. Uses the parameters as specified.
     *
     * @param[out] ct     the encrypted message
     * @param[out] ct_len the length of the encrypted message (`mlen` + `ct_size` + `kappa_bytes` + 16)
     * @param[in]  m      the message to encrypt
     * @param[in]  m_len  the length of the message to encrypt
     * @param[in]  pk     the public key to use for the encryption
     * @return __0__ in case of success
     */
    int r5_cca_pke_encrypt(uint8_t *ct, size_t *ct_len, const uint8_t *m, const size_t m_len, const uint8_t *pk, const uint8_t coins[32]);

    /**
     * Decrypts a message. Uses the parameters as specified.
     *
     * @param[out] m       the decrypted message
     * @param[out] m_len   the length of the decrypted message (`ct_len` - `ct_size` - `kappa_bytes` - 16)
     * @param[in]  ct      the message to decrypt
     * @param[in]  ct_len  the length of the message to decrypt
     * @param[in]  sk      the secret key to use for the decryption
     * @return __0__ in case of success
     */
    int r5_cca_pke_decrypt(uint8_t *m, size_t *m_len, const uint8_t *ct, const size_t ct_len, const uint8_t *sk);

#endif /* _R5_CCA_PKE_H_ */
