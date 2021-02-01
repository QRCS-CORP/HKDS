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
 * Updated on November 24, 2020
 * Contact: develop@dfdef.com
 */

#include "hkds_server.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include <omp.h>

static void hkds_server_generate_token(const uint8_t* stk, const uint8_t* ctok, uint8_t* token)
{
	uint8_t tkey[HKDS_CTOK_SIZE + HKDS_STK_SIZE] = { 0 };

	/* combine the custom token string and the token key */
	qsc_memutils_copy(tkey, ctok, HKDS_CTOK_SIZE);
	qsc_memutils_copy(((uint8_t*)tkey + HKDS_CTOK_SIZE), stk, HKDS_STK_SIZE);

	/* hash to generate the token */
#if defined(HKDS_SHAKE_128)
	qsc_shake128_compute(token, HKDS_STK_SIZE, tkey, sizeof(tkey));
#elif defined(HKDS_SHAKE_256)
	qsc_shake256_compute(token, HKDS_STK_SIZE, tkey, sizeof(tkey));
#else
	qsc_shake512_compute(token, HKDS_STK_SIZE, tkey, sizeof(tkey));
#endif
}

static void hkds_server_get_ctok(hkds_server_state* state, uint8_t* ctok)
{
	uint32_t tkc;

	/* add the token counter to customization string (ksn-counter / key-store size) */
	tkc = qsc_intutils_be8to32(((uint8_t*)state->ksn + HKDS_DID_SIZE)) / HKDS_CACHE_SIZE;
	qsc_intutils_be32to8(ctok, tkc);

	/* add the hkds_formal_name to customization string */
	qsc_memutils_copy(((uint8_t*)ctok + HKDS_TKC_SIZE), hkds_formal_name, HKDS_NAME_SIZE);
	/* add the clients identity string to the cutomization */
	qsc_memutils_copy(((uint8_t*)ctok + HKDS_TKC_SIZE + HKDS_NAME_SIZE), state->ksn, HKDS_DID_SIZE);
}

static void hkds_server_get_tms(uint8_t* ksn, uint8_t* tms)
{
	/* copy the ksn and mac name to the token mac string */
	qsc_memutils_copy(tms, ksn, HKDS_KSN_SIZE);
	qsc_memutils_copy(((uint8_t*)tms + HKDS_KSN_SIZE), hkds_mac_name, HKDS_NAME_SIZE);
}

static void hkds_server_generate_transaction_key(hkds_server_state* state, uint8_t* tkey, size_t tkeylen)
{
	uint8_t ctok[HKDS_CTOK_SIZE] = { 0 };
	uint8_t did[HKDS_DID_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	uint8_t skey[HKDS_CACHE_SIZE * HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tok[HKDS_STK_SIZE] = { 0 };
	uint8_t tmpk[HKDS_STK_SIZE + HKDS_EDK_SIZE] = { 0 };
	size_t nblocks;
	uint32_t index;

	/* get the key counter mod the cache size from the ksn */
	index = qsc_intutils_be8to32(((uint8_t*)state->ksn + HKDS_DID_SIZE)) % HKDS_CACHE_SIZE;

	/* copy the device id from the ksn */
	qsc_memutils_copy(did, state->ksn, HKDS_DID_SIZE);

	/* generate the device key */
	hkds_server_generate_edk(state->mdk->bdk, did, edk);

	/* generate the custom token string */
	hkds_server_get_ctok(state, ctok);

	/* generate the device token from the base token and customization string */
	hkds_server_generate_token(state->mdk->stk, ctok, tok);

	/* copy token and edk to PRF key */
	qsc_memutils_copy(tmpk, tok, HKDS_STK_SIZE);
	qsc_memutils_copy(((uint8_t*)tmpk + HKDS_STK_SIZE), edk, HKDS_EDK_SIZE);

	qsc_keccak_state ks;
	qsc_memutils_clear((uint8_t*)ks.state, QSC_KECCAK_STATE_SIZE * sizeof(uint64_t));

	/* generate the minimum number of blocks, and return the transaction key */
#if defined(HKDS_SHAKE_128)
	nblocks = ((index * HKDS_MESSAGE_SIZE) + tkeylen) / QSC_KECCAK_128_RATE;
	nblocks = (nblocks * QSC_KECCAK_128_RATE) < ((index * HKDS_MESSAGE_SIZE) + tkeylen) ? nblocks + 1 : nblocks;
	qsc_shake_initialize(&ks, keccak_rate_128, tmpk, sizeof(tmpk));
	qsc_shake_squeezeblocks(&ks, keccak_rate_128, skey, nblocks);
#elif defined(HKDS_SHAKE_256)
	nblocks = (((size_t)index * HKDS_MESSAGE_SIZE) + tkeylen) / QSC_KECCAK_256_RATE;
	nblocks = (nblocks * QSC_KECCAK_256_RATE) < (((size_t)index * HKDS_MESSAGE_SIZE) + tkeylen) ? nblocks + 1 : nblocks;
	qsc_shake_initialize(&ks, keccak_rate_256, tmpk, sizeof(tmpk));
	qsc_shake_squeezeblocks(&ks, keccak_rate_256, skey, nblocks);
#else
	nblocks = ((index * HKDS_MESSAGE_SIZE) + tkeylen) / QSC_KECCAK_512_RATE;
	nblocks = (nblocks * QSC_KECCAK_512_RATE) < ((index * HKDS_MESSAGE_SIZE) + tkeylen) ? nblocks + 1 : nblocks;
	qsc_shake_initialize(&ks, keccak_rate_512, tmpk, sizeof(tmpk));
	qsc_shake_squeezeblocks(&ks, keccak_rate_512, skey, nblocks);
#endif

	/* copy the cache key to the transaction key */
	qsc_memutils_copy(tkey, ((uint8_t*)skey + ((size_t)index * HKDS_MESSAGE_SIZE)), tkeylen);
}

void hkds_server_decrypt_message(hkds_server_state* state, const uint8_t* ciphertext, uint8_t* plaintext)
{
	/* copy the key directly into the empty plaintext array */
	hkds_server_generate_transaction_key(state, plaintext, HKDS_MESSAGE_SIZE);

	/* XOR the key-stream and cipher-text */
	qsc_memutils_xor(plaintext, ciphertext, HKDS_MESSAGE_SIZE);
}

bool hkds_server_decrypt_verify_message(hkds_server_state* state, const uint8_t* ciphertext, const uint8_t* data, size_t datalen, uint8_t* plaintext)
{
	uint8_t code[HKDS_TAG_SIZE] = { 0 };
	uint8_t dkey[2 * HKDS_MESSAGE_SIZE] = { 0 };
	size_t i;
	bool res;

	res = false;

	/* derive the transaction key  */
	hkds_server_generate_transaction_key(state, dkey, sizeof(dkey));

	/* generate the MAC code for the cipher-text received */
#if defined(HKDS_SHAKE_128)
	qsc_kmac128_compute(code, sizeof(code), ciphertext, HKDS_MESSAGE_SIZE, dkey + HKDS_MESSAGE_SIZE, HKDS_MESSAGE_SIZE, data, datalen);
#elif defined(HKDS_SHAKE_256)
	qsc_kmac256_compute(code, sizeof(code), ciphertext, HKDS_MESSAGE_SIZE, dkey + HKDS_MESSAGE_SIZE, HKDS_MESSAGE_SIZE, data, datalen);
#else
	qsc_kmac512_compute(code, sizeof(code), ciphertext, HKDS_MESSAGE_SIZE, dkey + HKDS_MESSAGE_SIZE, HKDS_MESSAGE_SIZE, data, datalen);
#endif

	/* compare the MAC generated with the one appended to the message */
	if (qsc_intutils_verify(code, ((uint8_t*)ciphertext + HKDS_MESSAGE_SIZE), HKDS_TAG_SIZE) == 0)
	{
		/* if the MAC check succeeds, decrypt the message */
		for (i = 0; i < HKDS_MESSAGE_SIZE; ++i)
		{
			plaintext[i] = (uint8_t)(ciphertext[i] ^ dkey[i]);
		}

		res = true;
	}

	return res;
}

void hkds_server_generate_edk(const uint8_t* bdk, const uint8_t* did, uint8_t* edk)
{
	uint8_t dkey[HKDS_BDK_SIZE + HKDS_DID_SIZE] = { 0 };

	/* copy the did and bdk to the key */
	qsc_memutils_copy(dkey, did, HKDS_DID_SIZE);
	qsc_memutils_copy(((uint8_t*)dkey + HKDS_DID_SIZE), bdk, HKDS_BDK_SIZE);

	/* hash key to generate edk */
#if defined(HKDS_SHAKE_128)
	qsc_shake128_compute(edk, HKDS_EDK_SIZE, dkey, sizeof(dkey));
#elif defined(HKDS_SHAKE_256)
	qsc_shake256_compute(edk, HKDS_EDK_SIZE, dkey, sizeof(dkey));
#else
	qsc_shake512_compute(edk, HKDS_EDK_SIZE, dkey, sizeof(dkey));
#endif
}

void hkds_server_encrypt_token(hkds_server_state* state, uint8_t* etok)
{
	uint8_t ctok[HKDS_CTOK_SIZE] = { 0 };
	uint8_t did[HKDS_DID_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	uint8_t tms[HKDS_TMS_SIZE] = { 0 };
	uint8_t tmpk[HKDS_CTOK_SIZE + HKDS_EDK_SIZE] = { 0 };
	uint8_t tok[HKDS_STK_SIZE] = { 0 };

	/* copy the device id from the ksn */
	qsc_memutils_copy(did, state->ksn, HKDS_DID_SIZE);

	/* generate the embedded device key */
	hkds_server_generate_edk(state->mdk->bdk, did, edk);

	/* generate the custom token string */
	hkds_server_get_ctok(state, ctok);

	/* generate the device token from the base token and customization string */
	hkds_server_generate_token(state->mdk->stk, ctok, tok);

	/* copy ctok and edk to PRF key */
	qsc_memutils_copy(tmpk, ctok, HKDS_CTOK_SIZE);
	qsc_memutils_copy(((uint8_t*)tmpk + HKDS_CTOK_SIZE), edk, HKDS_EDK_SIZE);

	/* initialize shake with the ctok and edk, and generate the encryption key */
#if defined(HKDS_SHAKE_128)
	qsc_shake128_compute(etok, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#elif defined(HKDS_SHAKE_256)
	qsc_shake256_compute(etok, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#else
	qsc_shake512_compute(etok, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#endif

	/* encrypt the token */
	qsc_memutils_xor(etok, tok, HKDS_STK_SIZE);

	/* get the token mac key string */
	hkds_server_get_tms(state->ksn, tms);

	/* M(tok, etok, tms) = kmac(m, k, c) */
#if defined(HKDS_SHAKE_128)
	qsc_kmac128_compute(etok + HKDS_STK_SIZE, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#elif defined(HKDS_SHAKE_256)
	qsc_kmac256_compute(etok + HKDS_STK_SIZE, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#else
	qsc_kmac512_compute(etok + HKDS_STK_SIZE, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#endif
}

void hkds_server_generate_mdk(void (*rng_generate)(uint8_t*, size_t), hkds_master_key* mdk, const uint8_t* kid)
{
	uint8_t tmpr[HKDS_BDK_SIZE + HKDS_STK_SIZE] = { 0 };

	rng_generate(tmpr, sizeof(tmpr));
	qsc_memutils_copy(mdk->bdk, tmpr, HKDS_BDK_SIZE);
	qsc_memutils_copy(mdk->stk, ((uint8_t*)tmpr + HKDS_BDK_SIZE), HKDS_STK_SIZE);
	qsc_memutils_copy(mdk->kid, kid, HKDS_KID_SIZE);
}

void hkds_server_initialize_state(hkds_server_state* state, hkds_master_key* mdk, const uint8_t* ksn)
{
	qsc_memutils_copy(state->ksn, ksn, HKDS_KSN_SIZE);
	state->mdk = mdk;
	state->count = qsc_intutils_be8to32(((uint8_t*)ksn + HKDS_DID_SIZE));
	state->rate = HKDS_PRF_RATE;
}

/* parallel x8 */

static void hkds_server_generate_token_x8(hkds_server_x8_state* state, 
	const uint8_t ctok[HKDS_CACHX8_DEPTH][HKDS_CTOK_SIZE], 
	uint8_t token[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE])
{
	uint8_t tkey[HKDS_CACHX8_DEPTH][HKDS_CTOK_SIZE + HKDS_STK_SIZE] = { 0 };
	size_t i;

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_copy(tkey[i], ctok[i], HKDS_CTOK_SIZE);
		qsc_memutils_copy(((uint8_t*)tkey[i] + HKDS_CTOK_SIZE), state->mdk->stk, HKDS_STK_SIZE);
	}

#if defined(HKDS_SHAKE_128)
	shake128x8(token[0], token[1], token[2], token[3], token[4], token[5], token[6], token[7], HKDS_STK_SIZE,
		tkey[0], tkey[1], tkey[2], tkey[3], tkey[4], tkey[5], tkey[6], tkey[7], HKDS_CTOK_SIZE + HKDS_STK_SIZE);
#elif defined(HKDS_SHAKE_256)
	shake256x8(token[0], token[1], token[2], token[3], token[4], token[5], token[6], token[7], HKDS_STK_SIZE,
		tkey[0], tkey[1], tkey[2], tkey[3], tkey[4], tkey[5], tkey[6], tkey[7], HKDS_CTOK_SIZE + HKDS_STK_SIZE);
#else
	shake512x8(token[0], token[1], token[2], token[3], token[4], token[5], token[6], token[7], HKDS_STK_SIZE,
		tkey[0], tkey[1], tkey[2], tkey[3], tkey[4], tkey[5], tkey[6], tkey[7], HKDS_CTOK_SIZE + HKDS_STK_SIZE);
#endif
}

static void hkds_server_get_ctok_x8(hkds_server_x8_state* state, 
	uint8_t ctok[HKDS_CACHX8_DEPTH][HKDS_CTOK_SIZE])
{
	uint32_t tkc[HKDS_CACHX8_DEPTH] = { 0 };
	size_t i;

	/* add the token counter to customization string (ksn-counter / key-store size) */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		tkc[i] = qsc_intutils_be8to32(((uint8_t*)state->ksn[i] + HKDS_DID_SIZE)) / HKDS_CACHE_SIZE;
		qsc_intutils_be32to8(ctok[i], tkc[i]);
		/* add the mode hkds_formal_name to customization string */
		qsc_memutils_copy(((uint8_t*)ctok[i] + HKDS_TKC_SIZE), hkds_formal_name, HKDS_NAME_SIZE);
		/* add the clients identity string to the cutomization */
		qsc_memutils_copy(((uint8_t*)ctok[i] + HKDS_TKC_SIZE + HKDS_NAME_SIZE), state->ksn[i], HKDS_DID_SIZE);
	}
}

static void hkds_server_generate_transaction_key_x8(hkds_server_x8_state* state, 
	uint8_t tkey[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE])
{
	uint8_t ctok[HKDS_CACHX8_DEPTH][HKDS_CTOK_SIZE] = { 0 };
	uint8_t did[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE] = { 0 };
	uint8_t edk[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE] = { 0 };
	uint8_t skey[HKDS_CACHX8_DEPTH][HKDS_CACHE_SIZE * HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tok[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE] = { 0 };
	uint8_t tmpk[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_EDK_SIZE] = { 0 };
	uint32_t index[HKDS_CACHX8_DEPTH] = { 0 };
	size_t i;

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		/* get the key counter mod the cache size from the ksn */
		index[i] = qsc_intutils_be8to32(((uint8_t*)state->ksn[i] + HKDS_DID_SIZE)) % HKDS_CACHE_SIZE;
		/* copy the device id from the ksn */
		qsc_memutils_copy(did[i], state->ksn[i], HKDS_DID_SIZE);
	}

	/* generate the device key */
	hkds_server_generate_edk_x8(state, did, edk);

	/* generate the custom token string */
	hkds_server_get_ctok_x8(state, ctok);

	/* generate the device token from the base token and customization string */
	hkds_server_generate_token_x8(state, ctok, tok);

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		/* copy token and edk to PRF key */
		qsc_memutils_copy(tmpk[i], tok[i], HKDS_STK_SIZE);
		qsc_memutils_copy(((uint8_t*)tmpk[i] + HKDS_STK_SIZE), edk[i], HKDS_EDK_SIZE);
	}

	/* generate the minimum number of blocks, and return the transaction key */
#if defined(HKDS_SHAKE_128)
	shake128x8(skey[0], skey[1], skey[2], skey[3], skey[4], skey[5], skey[6], skey[7], sizeof(skey[0]),
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_STK_SIZE + HKDS_EDK_SIZE);
#elif defined(HKDS_SHAKE_256)
	shake256x8(skey[0], skey[1], skey[2], skey[3], skey[4], skey[5], skey[6], skey[7], sizeof(skey[0]),
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_STK_SIZE + HKDS_EDK_SIZE);
#else
	shake512x8(skey[0], skey[1], skey[2], skey[3], skey[4], skey[5], skey[6], skey[7], sizeof(skey[0]),
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_STK_SIZE + HKDS_EDK_SIZE);
#endif

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_copy((uint8_t*)tkey[i], ((uint8_t*)skey[i] + ((size_t)index[i] * HKDS_MESSAGE_SIZE)), HKDS_MESSAGE_SIZE);
	}
}

static void hkds_server_generate_transaction_authkey_x8(hkds_server_x8_state* state, 
	uint8_t tkey[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE])
{
	uint8_t ctok[HKDS_CACHX8_DEPTH][HKDS_CTOK_SIZE] = { 0 };
	uint8_t did[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE] = { 0 };
	uint8_t edk[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE] = { 0 };
	uint8_t skey[HKDS_CACHX8_DEPTH][HKDS_CACHE_SIZE * HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tok[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE] = { 0 };
	uint8_t tmpk[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_EDK_SIZE] = { 0 };
	uint32_t index[HKDS_CACHX8_DEPTH] = { 0 };
	size_t i;

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		/* get the key counter mod the cache size from the ksn */
		index[i] = qsc_intutils_be8to32(((uint8_t*)state->ksn [i]+ HKDS_DID_SIZE)) % HKDS_CACHE_SIZE;
		/* copy the device id from the ksn */
		qsc_memutils_copy(did[i], state->ksn[i], HKDS_DID_SIZE);
	}

	/* generate the device key */
	hkds_server_generate_edk_x8(state, did, edk);

	/* generate the custom token string */
	hkds_server_get_ctok_x8(state, ctok);

	/* generate the device token from the base token and customization string */
	hkds_server_generate_token_x8(state, ctok, tok);

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		/* copy token and edk to PRF key */
		qsc_memutils_copy(tmpk[i], tok[i], HKDS_STK_SIZE);
		qsc_memutils_copy(((uint8_t*)tmpk[i] + HKDS_STK_SIZE), edk[i], HKDS_EDK_SIZE);
	}

	/* generate the minimum number of blocks, and return the transaction key */
#if defined(HKDS_SHAKE_128)
	shake128x8(skey[0], skey[1], skey[2], skey[3], skey[4], skey[5], skey[6], skey[7], sizeof(skey[0]),
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_STK_SIZE + HKDS_EDK_SIZE);
#elif defined(HKDS_SHAKE_256)
	shake256x8(skey[0], skey[1], skey[2], skey[3], skey[4], skey[5], skey[6], skey[7], sizeof(skey[0]),
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_STK_SIZE + HKDS_EDK_SIZE);
#else
	shake512x8(skey[0], skey[1], skey[2], skey[3], skey[4], skey[5], skey[6], skey[7], sizeof(skey[0]),
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_STK_SIZE + HKDS_EDK_SIZE);
#endif

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_copy((uint8_t*)tkey[i], ((uint8_t*)skey[i] + ((size_t)index[i] * HKDS_MESSAGE_SIZE)), 2 * HKDS_MESSAGE_SIZE);
	}
}

void hkds_server_decrypt_message_x8(hkds_server_x8_state* state, 
	const uint8_t ciphertext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], 
	uint8_t plaintext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE])
{
	size_t i;

	/* copy the key directly into the empty plaintext array */
	hkds_server_generate_transaction_key_x8(state, plaintext);

	/* XOR the key-stream and and cipher-text */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_xor(plaintext[i], ciphertext[i], HKDS_MESSAGE_SIZE);
	}
}

void hkds_server_encrypt_token_x8(hkds_server_x8_state* state, uint8_t etok[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE])
{
	uint8_t ctok[HKDS_CACHX8_DEPTH][HKDS_CTOK_SIZE] = { 0 };
	uint8_t did[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE] = { 0 };
	uint8_t edk[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE] = { 0 };
	uint8_t tms[HKDS_TMS_SIZE] = { 0 };
	uint8_t tmpk[HKDS_CACHX8_DEPTH][HKDS_CTOK_SIZE + HKDS_EDK_SIZE] = { 0 };
	uint8_t tok[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE] = { 0 };
	size_t i;

	/* copy the device id from the ksn */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_copy(did[i], state->ksn[i], HKDS_DID_SIZE);
	}

	/* generate the embedded device key */
	hkds_server_generate_edk_x8(state, did, edk);

	/* generate the custom token string */
	hkds_server_get_ctok_x8(state, ctok);

	/* generate the device token from the base token and customization string */
	hkds_server_generate_token_x8(state, ctok, tok);

	/* copy ctok and edk to PRF key */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_copy(tmpk[i], ctok[i], HKDS_CTOK_SIZE);
		qsc_memutils_copy(((uint8_t*)tmpk[i] + HKDS_CTOK_SIZE), edk[i], HKDS_EDK_SIZE);
	}

	/* initialize shake with the ctok and edk, and generate the encryption key */
#if defined(HKDS_SHAKE_128)
	shake128x8(etok[0], etok[1], etok[2], etok[3], etok[4], etok[5], etok[6], etok[7], HKDS_STK_SIZE,
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_CTOK_SIZE + HKDS_EDK_SIZE);
#elif defined(HKDS_SHAKE_256)
	shake256x8(etok[0], etok[1], etok[2], etok[3], etok[4], etok[5], etok[6], etok[7], HKDS_STK_SIZE,
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_CTOK_SIZE + HKDS_EDK_SIZE);
#else
	shake512x8(etok[0], etok[1], etok[2], etok[3], etok[4], etok[5], etok[6], etok[7], HKDS_STK_SIZE,
		tmpk[0], tmpk[1], tmpk[2], tmpk[3], tmpk[4], tmpk[5], tmpk[6], tmpk[7], HKDS_CTOK_SIZE + HKDS_EDK_SIZE);
#endif

	/* encrypt the token set */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_xor(etok[i], tok[i], HKDS_STK_SIZE);
	}

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_get_tms(state->ksn[i], tms);

#if defined(HKDS_SHAKE_128)
		qsc_kmac128_compute(etok[i] + HKDS_STK_SIZE, HKDS_TAG_SIZE, etok[i], HKDS_STK_SIZE, edk[i], HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#elif defined(HKDS_SHAKE_256)
		qsc_kmac256_compute(etok[i] + HKDS_STK_SIZE, HKDS_TAG_SIZE, etok[i], HKDS_STK_SIZE, edk[i], HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#else
		qsc_kmac512_compute(etok[i] + HKDS_STK_SIZE, HKDS_TAG_SIZE, etok[i], HKDS_STK_SIZE, edk[i], HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#endif
	}
}

void hkds_server_decrypt_verify_message_x8(hkds_server_x8_state* state, 
	const uint8_t ciphertext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE],
	const uint8_t data[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], size_t datalen, 
	uint8_t plaintext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], 
	bool valid[HKDS_CACHX8_DEPTH])
{
	uint8_t code[HKDS_CACHX8_DEPTH][HKDS_TAG_SIZE] = { 0 };
	uint8_t dkey[HKDS_CACHX8_DEPTH][2 * HKDS_MESSAGE_SIZE] = { 0 };
	size_t i;
	bool res;

	res = false;

	/* derive the transaction key  */
	hkds_server_generate_transaction_authkey_x8(state, dkey);

	/* generate the MAC code for the cipher-text received */
#if defined(HKDS_SHAKE_128)
	kmac128x8(code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7], HKDS_TAG_SIZE,
		((uint8_t*)dkey[0] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[1] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[2] + HKDS_MESSAGE_SIZE),
		((uint8_t*)dkey[3] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[4] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[5] + HKDS_MESSAGE_SIZE),
		((uint8_t*)dkey[6] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[7] + HKDS_MESSAGE_SIZE), HKDS_MESSAGE_SIZE,
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], datalen,
		ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], ciphertext[4],
		ciphertext[5], ciphertext[6], ciphertext[7], HKDS_MESSAGE_SIZE);
#elif defined(HKDS_SHAKE_256)
	kmac256x8(code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7], HKDS_TAG_SIZE,
		((uint8_t*)dkey[0] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[1] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[2] + HKDS_MESSAGE_SIZE),
		((uint8_t*)dkey[3] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[4] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[5] + HKDS_MESSAGE_SIZE),
		((uint8_t*)dkey[6] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[7] + HKDS_MESSAGE_SIZE), HKDS_MESSAGE_SIZE,
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], datalen,
		ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], ciphertext[4],
		ciphertext[5], ciphertext[6], ciphertext[7], HKDS_MESSAGE_SIZE);
#else
	kmac512x8(code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7], HKDS_TAG_SIZE,
		((uint8_t*)dkey[0] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[1] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[2] + HKDS_MESSAGE_SIZE),
		((uint8_t*)dkey[3] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[4] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[5] + HKDS_MESSAGE_SIZE),
		((uint8_t*)dkey[6] + HKDS_MESSAGE_SIZE), ((uint8_t*)dkey[7] + HKDS_MESSAGE_SIZE), HKDS_MESSAGE_SIZE,
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], datalen,
		ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], ciphertext[4],
		ciphertext[5], ciphertext[6], ciphertext[7], HKDS_MESSAGE_SIZE);
#endif

	/* compare the MAC generated with the one appended to the message */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		valid[i] = false;

		if (qsc_intutils_verify(code[i], ((uint8_t*)ciphertext[i] + HKDS_MESSAGE_SIZE), HKDS_TAG_SIZE) == 0)
		{
			/* if the MAC check succeeds, decrypt the message */
			qsc_memutils_copy(plaintext[i], ciphertext[i], HKDS_MESSAGE_SIZE);
			qsc_memutils_xor(plaintext[i], dkey[i], HKDS_MESSAGE_SIZE);
			valid[i] = true;
		}
	}
}

void hkds_server_generate_edk_x8(hkds_server_x8_state* state, 
	const uint8_t did[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE], 
	uint8_t edk[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE])
{
	uint8_t dkey[HKDS_CACHX8_DEPTH][HKDS_BDK_SIZE + HKDS_DID_SIZE] = { 0 };
	size_t i;

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_copy(dkey[i], did[i], HKDS_DID_SIZE);
		qsc_memutils_copy(((uint8_t*)dkey[i] + HKDS_DID_SIZE), state->mdk->bdk, HKDS_BDK_SIZE);
	}

#if defined(HKDS_SHAKE_128)
	shake128x8(edk[0], edk[1], edk[2], edk[3], edk[4], edk[5], edk[6], edk[7], HKDS_EDK_SIZE,
		dkey[0], dkey[1], dkey[2], dkey[3], dkey[4], dkey[5], dkey[6], dkey[7], sizeof(dkey[0]));
#elif defined(HKDS_SHAKE_256)
	shake256x8(edk[0], edk[1], edk[2], edk[3], edk[4], edk[5], edk[6], edk[7], HKDS_EDK_SIZE,
		dkey[0], dkey[1], dkey[2], dkey[3], dkey[4], dkey[5], dkey[6], dkey[7], sizeof(dkey[0]));
#else
	shake512x8(edk[0], edk[1], edk[2], edk[3], edk[4], edk[5], edk[6], edk[7], HKDS_EDK_SIZE,
		dkey[0], dkey[1], dkey[2], dkey[3], dkey[4], dkey[5], dkey[6], dkey[7], sizeof(dkey[0]));
#endif
}

void hkds_server_initialize_state_x8(hkds_server_x8_state* state, 
	hkds_master_key* mdk, const uint8_t 
	ksn[HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE])
{
	size_t i;

	state->mdk = mdk;

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		qsc_memutils_copy(state->ksn[i], ksn[i], HKDS_KSN_SIZE);
	}
}

/* parallel SIMD vectorized x64 api */

void hkds_server_decrypt_message_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH], 
	const uint8_t ciphertext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], 
	uint8_t plaintext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE])
{
	int32_t i;

#pragma omp parallel for shared(state, ciphertext, plaintext, i)
	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		hkds_server_decrypt_message_x8(&state[i], ciphertext[i], plaintext[i]);
	}
}

void hkds_server_decrypt_verify_message_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH], 
	const uint8_t ciphertext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE],
	const uint8_t data[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], size_t datalen, 
	uint8_t plaintext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], 
	bool valid[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH])
{
	int32_t i;

#pragma omp parallel for shared(state, ciphertext, data, datalen, plaintext, valid, i)
	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		hkds_server_decrypt_verify_message_x8(&state[i], ciphertext[i], data[i], datalen, plaintext[i], valid[i]);
	}
}

void hkds_server_encrypt_token_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH], uint8_t etok[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE])
{
	int32_t i;

#pragma omp parallel for shared(state, etok, i)
	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		hkds_server_encrypt_token_x8(&state[i], etok[i]);
	}
}

void hkds_server_generate_edk_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH], 
	const uint8_t did[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_DID_SIZE], 
	uint8_t edk[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE])
{
	int32_t i;

#pragma omp parallel for shared(state, did, edk, i)
	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		hkds_server_generate_edk_x8(&state[i], did[i], edk[i]);
	}
}

void hkds_server_initialize_state_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH], 
	hkds_master_key mdk[HKDS_PARALLEL_DEPTH], 
	const uint8_t ksn[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE])
{
	int32_t i;

#pragma omp parallel for shared(state, mdk, ksn, i)
	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		hkds_server_initialize_state_x8(&state[i], &mdk[i], ksn[i]);
	}
}
