//
//  rng.h
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include "rng.h"
#include "utils.h"

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

typedef struct {
    uint8_t Key[32];
    uint8_t V[16];
    int reseed_counter;
} AES256_CTR_DRBG_struct;

void
AES256_CTR_DRBG_Update(uint8_t *provided_data, uint8_t *Key, uint8_t *V);

//
//  rng.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

AES256_CTR_DRBG_struct DRBG_ctx;

void AES256_ECB(uint8_t *key, uint8_t *ctr, uint8_t *buffer);

static void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ctr - a 128-bit plaintext value
//    buffer - a 128-bit ciphertext value

void
AES256_ECB(uint8_t *key, uint8_t *ctr, uint8_t *buffer) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, buffer, &len, ctr, 16))
        handleErrors();
    ciphertext_len = len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void
randombytes_init(uint8_t *entropy_input,
        uint8_t *personalization_string,
        int security_strength) {
    uint8_t seed_material[48];

    copy_u8(seed_material, entropy_input, 48);
    if (personalization_string)
        for (int i = 0; i < 48; i++)
            seed_material[i] ^= personalization_string[i];
    zero_u8(DRBG_ctx.Key, 32);
    zero_u8(DRBG_ctx.V, 16);
    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

int
randombytes(uint8_t *x, size_t xlen) {
    uint8_t block[16];
    int i = 0;

    while (xlen > 0) {
        //increment V
        for (int j = 15; j >= 0; j--) {
            if (DRBG_ctx.V[j] == 0xff)
                DRBG_ctx.V[j] = 0x00;
            else {
                DRBG_ctx.V[j]++;
                break;
            }
        }
        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);
        if (xlen > 15) {
            copy_u8(x + i, block, 16);
            i += 16;
            xlen -= 16;
        } else {
            copy_u8(x + i, block, xlen);
            xlen = 0;
        }
    }
    AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter++;

    return RNG_SUCCESS;
}

void
AES256_CTR_DRBG_Update(uint8_t *provided_data,
        uint8_t *Key,
        uint8_t *V) {
    uint8_t temp[48];

    for (int i = 0; i < 3; i++) {
        //increment V
        for (int j = 15; j >= 0; j--) {
            if (V[j] == 0xff)
                V[j] = 0x00;
            else {
                V[j]++;
                break;
            }
        }

        AES256_ECB(Key, V, temp + 16 * i);
    }
    if (provided_data != NULL)
        for (int i = 0; i < 48; i++)
            temp[i] ^= provided_data[i];
    copy_u8(Key, temp, 32);
    copy_u8(V, temp + 32, 16);
}
