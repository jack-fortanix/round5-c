#include "r5_parameter_sets.h"
#include "r5_cca_pke.h"
#include "rng.h"

/**
     * Generates an ENCRYPT key pair.
     *
     * @param[out] pk public key
     * @param[out] sk secret key
     * @return __0__ in case of success
     */
    int crypto_encrypt_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t coins[3*32];
    randombytes(coins, 32);
    randombytes(coins + 32, 32);
    randombytes(coins + 64, 32);
    return r5_cca_pke_keygen(pk, sk, coins);
    }

    /**
     * Encrypts a message.
     *
     * @param[out] ct     the encrypted message
     * @param[out] ct_len the length of the encrypted message (`CRYPTO_CIPHERTEXTBYTES` + `m_len`)
     * @param[in]  m      the message to encrypt
     * @param[in]  m_len  the length of the message to encrypt
     * @param[in]  pk     the public key to use for the encryption
     * @return __0__ in case of success
     */
    int crypto_encrypt(uint8_t *ct, size_t *ct_len, const uint8_t *m, const size_t m_len, const uint8_t *pk) {
    uint8_t coins[32];
    randombytes(coins, 32);
    return r5_cca_pke_encrypt(ct, ct_len, m, m_len, pk, coins);
    }

    /**
     * Decrypts a message.
     *
     * @param[out] m      the decrypted message
     * @param[out] m_len  the length of the decrypted message (`ct_len` - `CRYPTO_CIPHERTEXTBYTES`)
     * @param[in]  ct     the message to decrypt
     * @param[in]  ct_len the length of the message to decrypt
     * @param[in]  sk     the secret key to use for the decryption
     * @return __0__ in case of success
     */
    int crypto_encrypt_open(uint8_t *m, size_t *m_len, const uint8_t *ct, const size_t ct_len, const uint8_t *sk) {
        return r5_cca_pke_decrypt(m, m_len, ct, ct_len, sk);
    }
