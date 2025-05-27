#include "hkds_client.h"
#include "keccak.h"
#include "utils.h"

static void hkds_client_generate_transaction_key(hkds_client_state* state, uint8_t* tkey)
{
	size_t idx;

	/* extract the index value */
	idx = (size_t)utils_integer_be8to32(((uint8_t*)state->ksn + HKDS_DID_SIZE)) % HKDS_CACHE_SIZE;
	/* copy the key and erase from cache memory */
	utils_memory_copy(tkey, state->tkc[idx], HKDS_MESSAGE_SIZE);
	utils_memory_clear(state->tkc[idx], HKDS_MESSAGE_SIZE);
	/* increment the index counter */
	utils_integer_be8increment(((uint8_t*)state->ksn + HKDS_DID_SIZE), HKDS_TKC_SIZE);

	if (idx == HKDS_CACHE_SIZE - 1U)
	{
		state->cache_empty = true;
	}
}

static void hkds_client_get_tms(const hkds_client_state* state, uint8_t* tms)
{
	/* copy the ksn and mac name to the token mac string */
	utils_memory_copy(tms, state->ksn, HKDS_KSN_SIZE);
	utils_memory_copy((tms + HKDS_KSN_SIZE), hkds_mac_name, HKDS_NAME_SIZE);
}

bool hkds_client_decrypt_token(hkds_client_state* state, const uint8_t* etok, uint8_t* token)
{
	uint8_t ctok[HKDS_CTOK_SIZE] = { 0U };
	uint8_t mtk[HKDS_TAG_SIZE] = { 0U };
	uint8_t tms[HKDS_TMS_SIZE] = { 0U };
	uint8_t tmpk[HKDS_CTOK_SIZE + HKDS_EDK_SIZE] = { 0U };
	uint32_t tkc;
	bool res;

	/* add the cache counter to customization string (tkc = transaction-counter / key-store size) */
	tkc = utils_integer_be8to32(((uint8_t*)state->ksn + HKDS_DID_SIZE)) / HKDS_CACHE_SIZE;
	utils_integer_be32to8(ctok, tkc);

	/* add the mode algorithm name to customization string */
	utils_memory_copy(((uint8_t*)ctok + HKDS_TKC_SIZE), hkds_formal_name, HKDS_NAME_SIZE);
	/* add the device id to the customization string */
	utils_memory_copy(((uint8_t*)ctok + HKDS_TKC_SIZE + HKDS_NAME_SIZE), state->ksn, HKDS_DID_SIZE);

	res = false;

	/* get the token mac key string */
	hkds_client_get_tms(state, tms);

	/* M(tok, etok, tms) = kmac(m, k, c) */
#if defined(HKDS_SHAKE_128)
	hkds_kmac128_compute(mtk, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, state->edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#elif defined(HKDS_SHAKE_256)
	hkds_kmac256_compute(mtk, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, state->edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#else
	hkds_kmac512_compute(mtk, HKDS_TAG_SIZE, etok, HKDS_STK_SIZE, state->edk, HKDS_EDK_SIZE, tms, HKDS_TMS_SIZE);
#endif

	/* compare the MAC generated with the one appended to the token message */
	if (utils_integer_verify(etok + HKDS_STK_SIZE, mtk, HKDS_TAG_SIZE) == 0)
	{
		/* if the MAC check succeeds, decrypt the message */
		res = true;
	}

	if (res == true)
	{
		/* combine ctok and edk to create the key */
		utils_memory_copy(tmpk, ctok, HKDS_CTOK_SIZE);
		utils_memory_copy(((uint8_t*)tmpk + HKDS_CTOK_SIZE), state->edk, HKDS_EDK_SIZE);

		/* initialize shake with device key and custom string, and generate the key-stream */
#if defined(HKDS_SHAKE_128)
		hkds_shake128_compute(token, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#elif defined(HKDS_SHAKE_256)
		hkds_shake256_compute(token, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#else
		hkds_shake512_compute(token, HKDS_STK_SIZE, tmpk, sizeof(tmpk));
#endif

		/* decrypt the token */
		for (size_t i = 0U; i < HKDS_STK_SIZE; ++i)
		{
			token[i] ^= etok[i];
		}
	}

	return res;
}

bool hkds_client_encrypt_message(hkds_client_state* state, const uint8_t* plaintext, uint8_t* ciphertext)
{
	bool res;

	res = false;

	if (state->cache_empty == false)
	{
		/* extract the transaction key */
		hkds_client_generate_transaction_key(state, ciphertext);

		/* encrypt the message */
		for (size_t i = 0U; i < HKDS_MESSAGE_SIZE; ++i)
		{
			ciphertext[i] ^= plaintext[i];
		}

		res = true;
	}

	return res;
}

bool hkds_client_encrypt_authenticate_message(hkds_client_state* state, const uint8_t* plaintext, const uint8_t* data, size_t datalen, uint8_t* ciphertext)
{
	uint8_t code[HKDS_TAG_SIZE] = { 0U };
	uint8_t ctxt[HKDS_MESSAGE_SIZE] = { 0U };
	uint8_t hkey[HKDS_MESSAGE_SIZE] = { 0U };
	bool res;

	res = false;

	/* extract the encryption key */
	if (state->cache_empty == false)
	{
		/* extract the transaction key */
		hkds_client_generate_transaction_key(state, ctxt);

		/* encrypt the message */
		for (size_t i = 0U; i < HKDS_MESSAGE_SIZE; ++i)
		{
			ctxt[i] ^= plaintext[i];
		}
	}

	if (state->cache_empty == false)
	{
		/* extract the MAC key */
		hkds_client_generate_transaction_key(state, hkey);

		/* initialize KMAC and generate the MAC tag */
#if defined(HKDS_SHAKE_128)
		hkds_kmac128_compute(code, sizeof(code), ctxt, sizeof(ctxt), hkey, sizeof(hkey), data, datalen);
#elif defined(HKDS_SHAKE_256)
		hkds_kmac256_compute(code, sizeof(code), ctxt, sizeof(ctxt), hkey, sizeof(hkey), data, datalen);
#else
		hkds_kmac512_compute(code, sizeof(code), ctxt, sizeof(ctxt), hkey, sizeof(hkey), data, datalen);
#endif

		/* copy cipher-text and MAC tag to cryptogram */
		utils_memory_copy(ciphertext, ctxt, sizeof(ctxt));
		utils_memory_copy((ciphertext + sizeof(ctxt)), code, sizeof(code));

		res = true;
	}

	return res;
}

void hkds_client_generate_cache(hkds_client_state* state, const uint8_t* token)
{
	uint8_t skey[HKDS_CACHE_SIZE * HKDS_MESSAGE_SIZE] = { 0U };
	uint8_t tmpk[HKDS_STK_SIZE + HKDS_EDK_SIZE] = { 0U };

	/* combine the token and edk keys */
	utils_memory_copy(tmpk, token, HKDS_STK_SIZE);
	utils_memory_copy(((uint8_t*)tmpk + HKDS_STK_SIZE), state->edk, HKDS_EDK_SIZE);

	/* generate the transaction key-cache */
#if defined(HKDS_SHAKE_128)
	hkds_shake128_compute(skey, sizeof(skey), tmpk, sizeof(tmpk));
#elif defined(HKDS_SHAKE_256)
	hkds_shake256_compute(skey, sizeof(skey), tmpk, sizeof(tmpk));
#else
	hkds_shake512_compute(skey, sizeof(skey), tmpk, sizeof(tmpk));
#endif

	/* copy keys to the queue */
	for (size_t i = 0U; i < HKDS_CACHE_SIZE; ++i)
	{
		utils_memory_copy(state->tkc[i], ((uint8_t*)skey + (i * HKDS_MESSAGE_SIZE)), HKDS_MESSAGE_SIZE);
	}

	state->cache_empty = false;
}

void hkds_client_initialize_state(hkds_client_state* state, const uint8_t* edk, const uint8_t* did)
{
	/* copy the edk and ksn, and clear the key-cache members */
	utils_memory_copy(state->edk, edk, HKDS_EDK_SIZE);
	utils_memory_copy(state->ksn, did, HKDS_DID_SIZE);
	utils_memory_clear(((uint8_t*)state->ksn + HKDS_DID_SIZE), HKDS_TKC_SIZE);

	for (size_t i = 0; i < HKDS_CACHE_SIZE; ++i)
	{
		utils_memory_clear(state->tkc[i], HKDS_MESSAGE_SIZE);
	}

	state->cache_empty = true;
}
