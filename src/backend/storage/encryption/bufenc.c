/*-------------------------------------------------------------------------
 *
 * bufenc.c
 *
 * Copyright (c) 2019, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/encryption/bufenc.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "storage/bufpage.h"
#include "storage/encryption.h"
#include "storage/fd.h"
#include "storage/kmgr.h"

static char buf_encryption_iv[ENC_IV_SIZE];
static char encryption_key_cache[TDE_MAX_DEK_SIZE];
static bool key_cached = false;

static void set_buffer_encryption_iv(Page page, BlockNumber blocknum);

void
EncryptBufferBlock(BlockNumber blocknum, Page page)
{
	/*
	 * Student TODO:
	 * This function should encrypt a buffer page "page", which has block number
	 * "blocknum" using a cached encryption key that the function will retrieve
	 * for you. "encryption_key_cache" variable below contains the key for you to
	 * complete this operation.
	 *
	 * REQUIREMENT:
	 * You must use "set_buffer_encryption_iv" to construct a IV value for this
	 * encryption operation.
	 *
	 * HINT:
	 * you are given the entire page contents in "page" including both the header
	 * and the actual data. If you just want to encrypt the actual data, you can
	 * use these macros defined in bufpage.h :
	 *
	 * 		#define PageEncryptOffset		offsetof(PageHeaderData, pd_linp)
	 * 		#define SizeOfPageEncryption	(BLCKSZ - PageEncryptOffset)
	 *
	 * 	where
	 * 		=> PageEncryptOffset is the offset value that you need to move your pointer
	 * 			or array to the start of the actual content
	 * 		=> SizeOfPageEncryption is the total size of the actual data minus the header
	 *
	 * you can called "pg_encrypt_data()" to complete the encryption
	 *
	 */
	if (!key_cached)
	{
		KmgrGetRelationEncryptionKey(encryption_key_cache);
		key_cached = true;
	}

	elog(WARNING, "[TDE] Entering %s...", __FUNCTION__);
	/******************* Your Code Starts Here ************************/



	/******************************************************************/
	elog(WARNING, "[TDE] Leaving %s...", __FUNCTION__);
}

void
DecryptBufferBlock(BlockNumber blocknum, Page page)
{
	/*
	 * Student TODO:
	 * This function should decrypt a buffer page "page", which has block number
	 * "blocknum" using a cached decryption key that the function will retrieve
	 * for you. "encryption_key_cache" variable below contains the key for you to
	 * complete this operation.
	 *
	 * REQUIREMENT:
	 * You must use "set_buffer_encryption_iv" to construct a IV value for this
	 * decryption operation.
	 *
	 * HINT:
	 * you are given the entire page contents in "page" including both the header
	 * and the actual data. If you just want to encrypt the actual data, you can
	 * use these macros defined in bufpage.h :
	 *
	 * 		#define PageEncryptOffset		offsetof(PageHeaderData, pd_linp)
	 * 		#define SizeOfPageEncryption	(BLCKSZ - PageEncryptOffset)
	 *
	 * 	where
	 * 		=> PageEncryptOffset is the offset value that you need to move your pointer
	 * 			or array to the start of the actual content
	 * 		=> SizeOfPageEncryption is the total size of the actual data minus the header
	 *
	 * 	you can called "pg_decrypt_data()" to complete the decryption
	 *
	 *
	 *
	 */
	if (!key_cached)
	{
		KmgrGetRelationEncryptionKey(encryption_key_cache);
		key_cached = true;
	}

	elog(WARNING, "[TDE] Entering %s...", __FUNCTION__);
	/******************* Your Code Starts Here ************************/



	/******************************************************************/
	elog(WARNING, "[TDE] Leaving %s...", __FUNCTION__);
}

/*
 * Nonce for buffer encryption consists of page lsn, block number
 * and counter. The counter is a counter value for CTR cipher mode.
 */
static void
set_buffer_encryption_iv(Page page, BlockNumber blocknum)
{
	/*
	 * Student TODO:
	 * This function should construct a new IV value using "blocknum" and the logical
	 * sequence number (lsn) that is stored in the header of "page. The lsn can be
	 * accessed like this:
	 *
	 * 		=>((PageHeader) page)->pd_lsn
	 *
	 * 	and has size
	 *
	 * 		=> sizeof(PageXLogRecPtr)
	 *
	 * The result of the IV value should be stored in the global array called
	 * "buf_encryption_iv" located in this file and its size is ENC_IV_SIZE,
	 * which is 16 bytes.
	 *
	 * HINT:
	 * 	You will find that by using "blocknum" and "pd_lsn" only, the size is still
	 * 	less than 16. Therefore, you will need to add something else in the construction
	 * 	of IV to make up the 16 byte length requirement. This "something" is up to you.
	 */
	char *p = buf_encryption_iv;

	MemSet(buf_encryption_iv, 0, ENC_IV_SIZE);

	elog(WARNING, "[TDE] Entering %s...", __FUNCTION__);
	/******************* Your Code Starts Here ************************/



	/******************************************************************/
	elog(WARNING, "[TDE] Leaving %s...", __FUNCTION__);

}

