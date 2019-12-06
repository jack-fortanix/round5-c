
//
//  PQCgenKAT_encrypt.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "api.h"
#include "utils.h"

#define	MAX_MARKER_LEN		50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, uint8_t *A, int Length, const char *str);
void	fprintBstr(FILE *fp, const char *S, uint8_t *A, size_t L);

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

static void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ctr - a 128-bit plaintext value
//    buffer - a 128-bit ciphertext value

static void
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

static void
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

static int
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

int
main()
{
    char                fn_req[32], fn_rsp[32];
    FILE                *fp_req, *fp_rsp;
    uint8_t       seed[48];
    uint8_t       msg[3300];
    uint8_t       entropy_input[48];
    uint8_t       *m, *c, *m1;
    size_t  mlen, clen, mlen1;
    int                 count;
    int                 done;
    uint8_t       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;
    
    // Create the REQUEST file
    sprintf(fn_req, "PQCencryptKAT_%d.req", CRYPTO_SECRETKEYBYTES);
    if ( (fp_req = fopen(fn_req, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    sprintf(fn_rsp, "PQCencryptKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    
    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for (int i=0; i<3; i++) {
        for (int j=0; j<25; j++) {
            fprintf(fp_req, "count = %d\n", i*25+j);
            randombytes(seed, 48);
            fprintBstr(fp_req, "seed = ", seed, 48);
            mlen = 16+i*8;
            fprintf(fp_req, "mlen = %zu\n", mlen);
            randombytes(msg, mlen);
            fprintBstr(fp_req, "msg = ", msg, mlen);
            fprintf(fp_req, "pk =\n");
            fprintf(fp_req, "sk =\n");
            fprintf(fp_req, "clen =\n");
            fprintf(fp_req, "c =\n\n");
        }
    }
    fclose(fp_req);
    
    //Create the RESPONSE file based on what's in the REQUEST file
    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    
    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    done = 0;
    do {
        if ( FindMarker(fp_req, "count = ") )
            fscanf(fp_req, "%d", &count);
        else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);
        
        if ( !ReadHex(fp_req, seed, 48, "seed = ") ) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);
        
        randombytes_init(seed, NULL, 256);
        
        if ( FindMarker(fp_req, "mlen = ") )
            fscanf(fp_req, "%zu", &mlen);
        else {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintf(fp_rsp, "mlen = %zu\n", mlen);
        
        m = (uint8_t *)calloc(mlen, sizeof(uint8_t));
        m1 = (uint8_t *)calloc(mlen+CRYPTO_BYTES, sizeof(uint8_t));
        c = (uint8_t *)calloc(mlen+CRYPTO_BYTES, sizeof(uint8_t));
        
        if ( !ReadHex(fp_req, m, (int)mlen, "msg = ") ) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "msg = ", m, mlen);

        uint8_t keygen_coins[3*32];
        randombytes(keygen_coins, 32);
        randombytes(keygen_coins+32, 32);
        randombytes(keygen_coins+64, 32);
        
        // Generate the public/private keypair
        if ( (ret_val = crypto_encrypt_keypair(pk, sk, keygen_coins)) != 0) {
            printf("crypto_encrypt_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

        uint8_t enc_coins[32];
        randombytes(enc_coins, 32);
        if ( (ret_val = crypto_encrypt(c, &clen, m, mlen, pk, enc_coins)) != 0) {
            printf("crypto_encrypt returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintf(fp_rsp, "clen = %zu\n", clen);
        fprintBstr(fp_rsp, "c = ", c, clen);
        fprintf(fp_rsp, "\n");
        
        if ( (ret_val = crypto_encrypt_open(m1, &mlen1, c, clen, sk)) != 0) {
            printf("crypto_encrypt_open returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        
        
        if ( mlen != mlen1 ) {
            printf("crypto_encrypt_open returned bad 'mlen': Got <%zu>, expected <%zu>\n", mlen1, mlen);
            return KAT_CRYPTO_FAILURE;
        }
        
        if ( memcmp(m, m1, mlen) ) {
            printf("crypto_encrypt_open returned bad 'm' value\n");
            return KAT_CRYPTO_FAILURE;
        }
        
        free(m);
        free(m1);
        free(c);

    } while ( !done );
    
    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, uint8_t *A, int Length, const char *str)
{
	int			i, ch, started;
	uint8_t	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;
			
			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, const char *S, uint8_t *A, size_t L)
{
	size_t  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

