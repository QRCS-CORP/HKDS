/* 2020 Digital Freedom Defense Incorporated
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Digital Freedom Defense Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Digital Freedom Defense Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Digital Freedom Defense Incorporated.
 *
 * Written by John G. Underhill
 * Written on March 29, 2020
 * Updated on May 24, 2020
 * Contact: develop@dfdef.com
 */

#include "hkds_client.h"
#include "../QSC/intutils.h"
#include "../QSC/sha3.h"

static void hkds_client_generate_transactionkey(hkds_client_state* state, uint8_t* tkey)
{
	size_t idx;

	/* extract the index value */
	idx = qsc_intutils_be8to32(((uint8_t*)state->ksn + HKDS_DID_SIZE)) % HKDS_CACHE_SIZE;
	/* copy the key and erase from cache memory */
	memcpy(tkey, state->tkc[idx], HKDS_MESSAGE_SIZE);
	memset(state->tkc[idx], 0x00, HKDS_MESSAGE_SIZE);
	/* increment the index counter */
	qsc_intutils_be8increment(((uint8_t*)state->ksn + HKDS_DID_SIZE), HKDS_TKC_SIZE);

	if (idx == HKDS_CACHE_SIZE - 1)
	{
		state->cache_empty = true;
	}
}

static void hkds_client_get_tms(hkds_client_state* state, uint8_t* tms)
{
	/* copy the ksn and mac name to the token mac string */
	memcpy(tms, state->ksn, HKDS_KSN_SIZE);
	memcpy(((uint8_t*)tms + HKDS_KSN_SIZE), hkds_mac_name, HKDS_NAME_SIZE);
}

bool hkds_client_decrypt_token(hkds_client_state* state, const uint8_t* etok, uint8_t* token)
{
	uint8_t ctok[HKDS_CTOK_SIZE] = { 0 };
	uint8_t mtk[HKDS_TAG_SIZE] = { 0 };
	uint8_t tms[HKDS_TMS_SIZE] = { 0 };
	uint8_t tmpk[HKDS_CTOK_SIZE + HKDS_EDK_SIZE] = { 0 };
	size_t i;
	uint32_t tkc;
	bool res;

	/* add the cache counter to customization string (tkc = transaction-counter / key-store size) */
	tkc = qsc_intutils_be8to32(((uint8_t*)state->ksn + HKDS_DID_SIZE)) / HKDS_CACHE_SIZE;
	qsc_intutils_be32to8(ctok, tkc);

	/* add the mode algorithm name to customization string */
	memcpy(((uint8_t*)ctok + HKDS_TKC_SIZE), hkds_formal_name, HKDS_NAME_SIZE);
	/* add the device id to the customization string */
	memcpy(((uint8_t*)ctok + HKDS_TKC_SIZE + HKDS_NAME_SIZE), state->ksn, HKDS_DID_SIZE);

	res = false;

	/* get the token mac key string */
	hkds_client_get_tms(state, tms);

	/* M(tok, etok, tms) = kmac(m, k, c) */
#if defined(HKDS_SHAKE_128)
	qsc_kmac128_compute(mtk, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, state->edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#elif defined(HKDS_SHAKE_256)
	qsc_kmac256_compute(mtk, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, state->edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#else
	qsc_kmac512_compute(mtk, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, state->edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#endif

	/* compare the MAC generated with the one appended to the token message */
	if (qsc_intutils_verify(etok + HKDS_STK_SIZE, mtk, HKDS_TAG_SIZE) == 0)
	{
		/* if the MAC check succeeds, decrypt the message */
		res = true;
	}

	if (res == true)
	{
		/* combine ctok and edk to create the key */
		memcpy(tmpk, ctok, HKDS_CTOK_SIZE);
		memcpy(((uint8_t*)tmpk + HKDS_CTOK_SIZE), state->edk, HKDS_EDK_SIZE);

		/* initialize shake with device key and custom string, and generate the key-stream */
#if defined(HKDS_SHAKE_128)
		qsc_shake128_compute(token, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#elif defined(HKDS_SHAKE_256)
		qsc_shake256_compute(token, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#else
		qsc_shake512_compute(token, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#endif

		/* decrypt the token */
		for (i = 0; i < HKDS_STK_SIZE; ++i)
		{
			token[i] ^= etok[i];
		}
	}

	return res;
}

bool hkds_client_encrypt_message(hkds_client_state* state, const uint8_t* plaintext, uint8_t* ciphertext)
{
	size_t i;
	bool res;

	res = false;

	if (state->cache_empty == false)
	{
		/* extract the transaction key */
		hkds_client_generate_transactionkey(state, ciphertext);

		/* encrypt the message */
		for (i = 0; i < HKDS_MESSAGE_SIZE; ++i)
		{
			ciphertext[i] ^= plaintext[i];
		}

		res = true;
	}

	return res;
}

bool hkds_client_encrypt_authenticate_message(hkds_client_state* state, const uint8_t* plaintext, const uint8_t* data, size_t datalen, uint8_t* ciphertext)
{
	uint8_t code[HKDS_TAG_SIZE] = { 0 };
	uint8_t ctxt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t hkey[HKDS_MESSAGE_SIZE] = { 0 };
	size_t i;
	bool res;

	res = false;

	/* extract the encryption key */
	if (state->cache_empty == false)
	{
		/* extract the transaction key */
		hkds_client_generate_transactionkey(state, ctxt);

		/* encrypt the message */
		for (i = 0; i < HKDS_MESSAGE_SIZE; ++i)
		{
			ctxt[i] ^= plaintext[i];
		}
	}

	if (state->cache_empty == false)
	{
		/* extract the MAC key */
		hkds_client_generate_transactionkey(state, hkey);

		/* initialize KMAC and generate the MAC tag */
#if defined(HKDS_SHAKE_128)
		qsc_kmac128_compute(code, sizeof(code), ctxt, sizeof(ctxt), hkey, sizeof(hkey), data, datalen);
#elif defined(HKDS_SHAKE_256)
		qsc_kmac256_compute(code, sizeof(code), ctxt, sizeof(ctxt), hkey, sizeof(hkey), data, datalen);
#else
		qsc_kmac512_compute(code, sizeof(code), ctxt, sizeof(ctxt), hkey, sizeof(hkey), data, datalen);
#endif

		/* copy cipher-text and MAC tag to cryptogram */
		memcpy(ciphertext, ctxt, sizeof(ctxt));
		memcpy(((uint8_t*)ciphertext + sizeof(ctxt)), code, sizeof(code));

		res = true;
	}

	return res;
}

void hkds_client_generate_cache(hkds_client_state* state, const uint8_t* token)
{
	uint8_t skey[HKDS_CACHE_SIZE * HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tmpk[HKDS_STK_SIZE + HKDS_EDK_SIZE] = { 0 };
	size_t i;

	/* combine the token and edk keys */
	memcpy(tmpk, token, HKDS_STK_SIZE);
	memcpy(((uint8_t*)tmpk + HKDS_STK_SIZE), state->edk, HKDS_EDK_SIZE);

	/* generate the transaction key-cache */
#if defined(HKDS_SHAKE_128)
	qsc_shake128_compute(skey, sizeof(skey), tmpk, sizeof(tmpk));
#elif defined(HKDS_SHAKE_256)
	qsc_shake256_compute(skey, sizeof(skey), tmpk, sizeof(tmpk));
#else
	qsc_shake512_compute(skey, sizeof(skey), tmpk, sizeof(tmpk));
#endif

	/* copy keys to the queue */
	for (i = 0; i < HKDS_CACHE_SIZE; ++i)
	{
		memcpy(state->tkc[i], ((uint8_t*)skey + (i * HKDS_MESSAGE_SIZE)), HKDS_MESSAGE_SIZE);
	}

	state->cache_empty = false;
}

void hkds_client_initialize_state(hkds_client_state* state, const uint8_t* edk, const uint8_t* did)
{
	size_t i;

	/* copy the edk and ksn, and clear the key-cache members */
	memcpy(state->edk, edk, HKDS_EDK_SIZE);
	memcpy(state->ksn, did, HKDS_DID_SIZE);
	memset(((uint8_t*)state->ksn + HKDS_DID_SIZE), 0x00, HKDS_TKC_SIZE);

	for (i = 0; i < HKDS_CACHE_SIZE; ++i)
	{
		memset(state->tkc[i], 0x00, HKDS_MESSAGE_SIZE);
	}


	state->cache_empty = true;
}
