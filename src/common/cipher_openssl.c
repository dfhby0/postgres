/*-------------------------------------------------------------------------
 * cipher_openssl.c
 *		Cryptographic function using OpenSSL
 *
 * This contains the common low-level functions needed in both frontend and
 * backend, for implement the database encryption.
 *
 * Portions Copyright (c) 2020, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/common/cipher_openssl.c
 *
 *-------------------------------------------------------------------------
 */
#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#include "common/sha2.h"
#include "common/cipher_openssl.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

/*
 * prototype for the EVP functions that return an algorithm, e.g.
 * EVP_aes_128_cbc().
 */
typedef const EVP_CIPHER *(*ossl_EVP_cipher_func) (void);

static bool ossl_initialized = false;

static bool ossl_cipher_setup(void);
static ossl_EVP_cipher_func get_evp_aes_cbc(int klen);

static bool
ossl_cipher_setup(void)
{
#ifdef HAVE_OPENSSL_INIT_CRYPTO
	/* Setup OpenSSL */
	if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
		return false;
#else
	OPENSSL_config(NULL);
#endif
	return false;
}

static ossl_EVP_cipher_func
get_evp_aes_cbc(int klen)
{
	switch (klen)
	{
		case PG_AES128_KEY_LEN:
			return EVP_aes_128_cbc;
		case PG_AES192_KEY_LEN:
			return EVP_aes_192_cbc;
		case PG_AES256_KEY_LEN:
			return EVP_aes_256_cbc;
		default:
			return NULL;
	}
}

/*
 * Initialize and return an EVP_CIPHER_CTX. Return NULL if the given
 * cipher algorithm is not supported or on failure..
 */
EVP_CIPHER_CTX *
ossl_cipher_ctx_create(int cipher, uint8 *key, int klen, bool enc)
{
	/*
	 * Student TODO:
	 * This function should create and initialize a new EVP_CIPHER_CTX using
	 * the input encryption key "key" and key length "klen" such that it can
	 * be used for the subsequent encryption or decryption operations.
	 *
	 * Based on the input "enc", the context shall be initialized for
	 * either encryption or decryption. For example, if "enc" is true, then
	 * the context should be initialized for encryption operation.
	 *
	 * When all is done without problems, the function returns a pointer to an
	 * initialized EVP_CIPHER_CTX.
	 *
	 * HINT:
	 * You should use get_evp_aes_cbc() function defined above to correctly
	 * returns a EVP_CIPHER to used based on the length of the key "klen".
	 * EVP_CIPHER is needed in EVP_EncryptInit_ex.
	 */

	EVP_CIPHER_CTX			*ctx;
	ossl_EVP_cipher_func	func;

	/******************* Your Code Starts Here ************************/



	/******************************************************************/

	return NULL;
}

void
ossl_cipher_ctx_free(EVP_CIPHER_CTX *ctx)
{
	/*
	 * Student TODO:
	 * This function should destroy and free the EVP_CIPHER_CTX
	 * passed as input called "ctx", so we will not have memory
	 * leak.
	 *
	 * inputs
	 * 		ctx		=> the encryption context to free
	 */

	/******************* Your Code Starts Here ************************/



	/******************************************************************/
}

bool
ossl_cipher_encrypt(EVP_CIPHER_CTX *ctx,
					const uint8 *in, int inlen,
					uint8 *out, int *outlen,
					const uint8 *iv)
{
	/*
	 * Student TODO:
	 * This function should use the input context "ctx" and try to
	 * encrypt the input data "in" of size "inlen using the IV value
	 * "iv" and produce an encrypted output. The output data should be
	 * stored in "out" and the output data length stored in "outlen"
	 *
	 * inputs
	 * 		ctx*	=> the encrpytion context to use. Should already
	 * 						been initialized
	 *		*in		=> the input data buffer to encrypt
	 *		inlen	=> the length of input data buffer
	 *		*iv		=> the initialization vector that you should use
	 *					in the encryption
	 *
	 * outputs:
	 *		*out	=> the output data buffer to store encrypted data
	 *		*outlen => the length of output data buffer stored
	 */

	/******************* Your Code Starts Here ************************/



	/******************************************************************/

	return false;
}

bool
ossl_cipher_decrypt(EVP_CIPHER_CTX *ctx,
					const uint8 *in, int inlen,
					uint8 *out, int *outlen,
					const uint8 *iv)
{
	/*
	 * Student TODO:
	 * This function should use the input context "ctx" and try to
	 * decrypt the input data "in" of size "inlen using the IV value
	 * "iv" and produce an decrypted output. The output data should be
	 * stored in "out" and the output data length stored in "outlen"
	 *
	 * inputs
	 * 		ctx*	=> the decryption context to use. Should already
	 * 						been initialized
	 *		*in		=> the input data buffer to decrypt
	 *		inlen	=> the length of input data buffer
	 *		*iv		=> the initialization vector that you should use
	 *					in the decryption
	 *
	 * outputs:
	 *		*out	=> the output data buffer to store decrypted data
	 *		*outlen => the length of output data buffer stored
	 */

	/******************* Your Code Starts Here ************************/



	/******************************************************************/

	return false;
}

bool
ossl_HMAC_SHA512(const uint8 *key, const uint8 *in, int inlen,
				 uint8 *out)
{
	/*
	 * Student TODO:
	 * This function should compute a SHA512 hash of "in" of size
	 * "inlen" using the hash key "key". The result of the computation
	 * should be stored in the "out" parameter. If success, true is returned
	 * otherwise, false is returned.
	 *
	 * inputs:
	 * 		key*	=> the hash key to use in SHA512 computation
	 *		*in		=> the input data buffer to compute hash
	 *		inlen	=> the length of input data buffer
	 *
	 *	outputs:
	 *		*out	=> the SHA512 hash output buffer
	 */

	/******************* Your Code Starts Here ************************/


	/******************************************************************/
}
