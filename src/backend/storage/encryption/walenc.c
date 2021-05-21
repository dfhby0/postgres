/*-------------------------------------------------------------------------
 *

 * walenc.c
 *
 * Copyright (c) 2019, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/encryption/walenc.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xlog.h"
#include "access/xlog_internal.h"
#include "storage/encryption.h"
#include "storage/kmgr.h"

static char wal_encryption_iv[ENC_IV_SIZE];
static char wal_encryption_buf[XLOG_BLCKSZ];
static char encryption_key_cache[TDE_MAX_DEK_SIZE];
static bool key_cached = false;

static void
set_wal_encryption_iv(XLogSegNo segment, uint32 offset)
{
	/*
	 * Student TODO:
	 * This function should construct a new IV value using "segment" and the "pageno"
	 * that can be calculated by :
	 *
	 * 		=> pageno = offset / XLOG_BLCKSZ;
	 *
	 * The result of the IV value should be stored in the global array called
	 * "wal_encryption_iv" located in this file and its size is ENC_IV_SIZE,
	 * which is 16 bytes.
	 *
	 * HINT:
	 * 	You will find that by using "segment" and "pageno" only, the size is still
	 * 	less than 16. Therefore, you will need to add something else in the construction
	 * 	of IV to make up the 16 byte length requirement. This "something" is up to you.
	 */

	char *p = wal_encryption_iv;

	MemSet(wal_encryption_iv, 0, ENC_IV_SIZE);

	elog(WARNING, "[TDE] Entering %s...", __FUNCTION__);
	/******************* Your Code Starts Here ************************/



	/******************************************************************/
	elog(WARNING, "[TDE] Leaving %s...", __FUNCTION__);
}

/*
 * Copy the contents of WAL page and encrypt it. Returns the copied and
 * encrypted WAL page.
 */
char *
EncryptXLog(char *page, Size nbytes, XLogSegNo segno, uint32 offset)
{
	/*
	 * Student TODO:
	 * This function should encrypt a WAL page "page", which has length of "nbytes".
	 * The "segno" and "offset" input parameters are for you to construct a IV
	 * value for the encryption operation. "encryption_key_cache" variable below
	 * contains the key for you to complete this operation.
	 *
	 * REQUIREMENT:
	 * You must use "set_wal_encryption_iv" to construct a IV value for this
	 * encryption operation using "segno" and "offset".
	 *
	 * HINT:
	 * you are given the entire page contents in "page" including both the header
	 * and the actual data. If you just want to encrypt the actual data, you can
	 * use these macros defined in bufpage.h :
	 *
	 * 		#define XLogEncryptionOffset	SizeOfXLogShortPHD
	 *
	 * 	where
	 * 		=> XLogEncryptionOffset is the offset value that you need to move your pointer
	 * 			or array to the start of the actual WAL content
	 *
	 * you can called "pg_encrypt_data()" to complete the encryption
	 *
	 */
	Assert(nbytes <= XLOG_BLCKSZ);

	if (!key_cached)
	{
		KmgrGetWALEncryptionKey(encryption_key_cache);
		key_cached = true;
	}

	elog(WARNING, "[TDE] Entering %s...", __FUNCTION__);
	/******************* Your Code Starts Here ************************/


	/******************************************************************/
	elog(WARNING, "[TDE] Leaving %s...", __FUNCTION__);

	return wal_encryption_buf;
}

/*
 * Decrypt a WAL page and return. Unlike EncryptXLog, this function encrypt
 * the given buffer directly.
 */
void
DecryptXLog(char *page, Size nbytes, XLogSegNo segno, uint32 offset)
{
	/*
	 * Student TODO:
	 * This function should decrypt a WAL page "page", which has length of "nbytes".
	 * The "segno" and "offset" input parameters are for you to construct a IV
	 * value for the encryption operation. "encryption_key_cache" variable below
	 * contains the key for you to complete this operation.
	 *
	 * REQUIREMENT:
	 * You must use "set_wal_encryption_iv" to construct a IV value for this
	 * encryption operation using "segno" and "offset".
	 *
	 * HINT:
	 * you are given the entire page contents in "page" including both the header
	 * and the actual data. If you just want to encrypt the actual data, you can
	 * use these macros defined in bufpage.h :
	 *
	 * 		#define XLogEncryptionOffset	SizeOfXLogShortPHD
	 *
	 * 	where
	 * 		=> XLogEncryptionOffset is the offset value that you need to move your pointer
	 * 			or array to the start of the actual WAL content
	 *
	 * you can called "pg_decrypt_data()" to complete the decryption
	 *
	 */
	Assert(nbytes <= XLOG_BLCKSZ);

	if (!key_cached)
	{
		KmgrGetWALEncryptionKey(encryption_key_cache);
		key_cached = true;
	}

	elog(WARNING, "[TDE] Entering %s...", __FUNCTION__);
	/******************* Your Code Starts Here ************************/



	/******************************************************************/
	elog(WARNING, "[TDE] Leaving %s...", __FUNCTION__);
}

