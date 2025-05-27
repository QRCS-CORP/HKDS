#include "hkds_test.h"
#include "testutils.h"
#include "../HKDS/hkds_client.h"
#include "../HKDS/hkds_server.h"
#include "../HKDS/utils.h"

#define HKDSTEST_CYCLES_COUNT 1000

/* Note: set the operation mode in hkds_config.h */

/* the PRF mode, SHAKE-128 = 9, SHAKE-256 = 10, SHAKE=512 = 11 */
#if defined(HKDS_SHAKE_128)
const uint8_t HKDSTEST_PRF_MODE = 0x09;
#elif defined(HKDS_SHAKE_256)
const uint8_t HKDSTEST_PRF_MODE = 0x0A;
#else
const uint8_t HKDSTEST_PRF_MODE = 0x0B;
#endif

bool hkdstest_cycle_test()
{
	/* the PRF mode, 0x0A for SHAKE-256 */
	const uint8_t PRFMODE = 0x0A;
	/* protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication */
	const uint8_t PID = 0x10;
	/* master key id */
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device id						|		BKD ID			| PID | Mode |	MID	   |			DID		   | */
	const uint8_t did[HKDS_DID_SIZE] = { 0x01, 0x00, 0x00, 0x00, PID, PRFMODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
	uint8_t cpt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t dec[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	uint8_t msg[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tokd[HKDS_STK_SIZE] = { 0 };
	uint8_t toke[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	bool res;

	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));
	res = true;

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_master_key mdk;
	hkds_server_generate_mdk(&utils_seed_generate, &mdk, kid);

	/* generate the clients embedded key */
	hkds_server_generate_edk(mdk.bdk, did, edk);

	/* initialize the client */
	hkds_client_state cs;
	hkds_client_initialize_state(&cs, edk, did);

	/* initialize the server with the client-ksn */
	hkds_server_state ss;
	hkds_server_initialize_state(&ss, &mdk, cs.ksn);

	/* client requests the token key from server */
	hkds_server_encrypt_token(&ss, toke);

	/* client decrypts the token */
	if (hkds_client_decrypt_token(&cs, toke, tokd) == false)
	{
		hkdstest_print_line("hkds_cycle_test: token authentication failure! -HCT1");
		res = false;
	}

	/* client derives the transaction key-set */
	hkds_client_generate_cache(&cs, tokd);

	/* client encrypts a message */
	hkds_client_encrypt_message(&cs, msg, cpt);

	/* server decrypts the message */
	hkds_server_decrypt_message(&ss, cpt, dec);

	if (utils_memory_are_equal(msg, dec, sizeof(msg)) == false)
	{
		hkdstest_print_line("hkds_cycle_test: decryption authentication failure! -HCT2");
		res = false;
	}

	return res;
}

bool hkdstest_kat_test()
{
	/* protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication */
	const uint8_t PID = 0x10;
	/* master key id */
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device id						|		BKD ID			| PID | Mode		|	MID	   |			DID		   | */
	const uint8_t did[HKDS_DID_SIZE] = { 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };

	uint8_t cpt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t dec[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	/* expected ciphertext output */
	uint8_t exp[HKDS_MESSAGE_SIZE] = { 0 };
	/* test master key and token */
	uint8_t key[HKDS_BDK_SIZE] = { 0 };
	uint8_t msg[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tokd[HKDS_STK_SIZE] = { 0 };
	uint8_t toke[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t tokm[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	bool res;

#if defined(HKDS_SHAKE_128)
	hkdstest_hex_to_bin("21EDC540F713649F38EDB3CB9E26336E", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hkdstest_hex_to_bin("EB519BE85D80BA42CD231AFD760AC67B238CC46114C28D75F6CBAB17D15F77CA", tokm, sizeof(tokm));
#elif defined(HKDS_SHAKE_256)
	hkdstest_hex_to_bin("4422FD14DC32CF52765227782B7DF346", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
	hkdstest_hex_to_bin("8F576DA2168C4582CE02F0E75665FCFD720131C3AB78DE46B7BD1F059AFBCC7D"
		"A83CF9F67FB17E3C3FB888F00A16AD2F", tokm, sizeof(tokm));
#else
	hkdstest_hex_to_bin("8F8237E723C13AC5C07BDDE483F586DB", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key, sizeof(key));
	hkdstest_hex_to_bin("FB2C5048D1E3BBB7937F2069C8523F7C3900C306526BB273F708CE2177CE5848"
		"D5C45B86B44FC2D4E705AA5AE49C85319202F600F4CAAE15CEC92AA29FD6D0CF"
		"EF48CAFB113BF594D6A7FDFD5FECAE36", tokm, sizeof(tokm));
#endif
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));

	res = true;

	/* test master-key with known values */
	hkds_master_key mdk;
	memcpy(mdk.bdk, key, sizeof(key));
	memcpy(mdk.stk, key, sizeof(key));
	memcpy(mdk.kid, kid, sizeof(kid));

	/* generate the clients embedded key */
	hkds_server_generate_edk(mdk.bdk, did, edk);

	/* initialize the client */
	hkds_client_state cs;
	hkds_client_initialize_state(&cs, edk, did);

	/* initialize the server with the client-ksn */
	hkds_server_state ss;
	hkds_server_initialize_state(&ss, &mdk, cs.ksn);

	/* client requests the token key from server */
	hkds_server_encrypt_token(&ss, toke);

	if (utils_memory_are_equal(toke, tokm, sizeof(toke)) == false)
	{
		hkdstest_print_line("hkds_kat_test: token does not match expected answer! -HKT1");
		res = false;
	}

	/* client decrypts the token */
	if (hkds_client_decrypt_token(&cs, toke, tokd) == false)
	{
		hkdstest_print_line("hkds_kat_test: token decryption failure! -HKT2");
		res = false;
	}

	/* client derives the transaction key-set */
	hkds_client_generate_cache(&cs, tokd);

	/* client encrypts a message */
	hkds_client_encrypt_message(&cs, msg, cpt);

	if (utils_memory_are_equal(cpt, exp, sizeof(cpt)) == false)
	{
		hkdstest_print_line("hkds_kat_test: ciphertext does not match expected answer! -HKT3");
		res = false;
	}

	/* server decrypts the message */
	hkds_server_decrypt_message(&ss, cpt, dec);

	if (utils_memory_are_equal(msg, dec, sizeof(msg)) == false)
	{
		hkdstest_print_line("hkds_kat_test: message decryption failure! -HKT4");
		res = false;
	}

	return res;
}

bool hkdstest_katae_test()
{
	/* protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication */
	const uint8_t PID = 0x11;
	/* master key id */
	const uint8_t ad[4] = { 0xC0, 0xA8, 0x00, 0x01 };
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device id						|		BKD ID			| PID | Mode		|	MID	   |			DID		   | */
	const uint8_t did[HKDS_DID_SIZE] = { 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
	uint8_t msg[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t cpt[HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t dec[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	/* expected ciphertext output */
	uint8_t exp[HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE] = { 0 };
	/* test master key and token */
	uint8_t key[HKDS_BDK_SIZE] = { 0 };
	uint8_t tokd[HKDS_STK_SIZE] = { 0 };
	uint8_t toke[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	bool res;

#if defined(HKDS_SHAKE_128)
	hkdstest_hex_to_bin("A0BFAB1B05D8005B0F8929A0DDF5BEF6510E048375C715319C3CCE6FA29D3C8F", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", key, sizeof(key));
#elif defined(HKDS_SHAKE_256)
	hkdstest_hex_to_bin("11A91FAE7C8019CF273EE74AB544631F0B3C56745578192379CD649EE591D488", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
#else
	hkdstest_hex_to_bin("0D818095417A9AA6DB9555B491348F3C8513E6196A67EC992719B324E5F2E58B", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key, sizeof(key));
#endif

	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));

	res = true;

	/* test master-key with known values */
	hkds_master_key mdk;
	memcpy(mdk.bdk, key, sizeof(key));
	memcpy(mdk.stk, key, sizeof(key));
	memcpy(mdk.kid, kid, sizeof(kid));

	/* generate the clients embedded key */
	hkds_server_generate_edk(mdk.bdk, did, edk);

	/* initialize the client */
	hkds_client_state cs;
	hkds_client_initialize_state(&cs, edk, did);

	/* initialize the server with the client-ksn */
	hkds_server_state ss;
	hkds_server_initialize_state(&ss, &mdk, cs.ksn);

	/* client requests the token key from server */
	hkds_server_encrypt_token(&ss, toke);

	/* client decrypts the token */
	if (hkds_client_decrypt_token(&cs, toke, tokd) == false)
	{
		hkdstest_print_line("hkds_katae_test: token authentication failure! -HKA1");
		res = false;
	}

	/* client derives the transaction key-set */
	hkds_client_generate_cache(&cs, tokd);

	/* client encrypts a message */
	hkds_client_encrypt_authenticate_message(&cs, msg, ad, sizeof(ad), cpt);

	if (utils_memory_are_equal(cpt, exp, sizeof(cpt)) == false)
	{
		hkdstest_print_line("hkds_katae_test: ciphertext does not match expected answer! -HKA2");
		res = false;
	}

	/* server decrypts the message */
	if (hkds_server_decrypt_verify_message(&ss, cpt, ad, sizeof(ad), dec) == false)
	{
		hkdstest_print_line("hkds_katae_test: decryption authentication failure! -HKA3");
		res = false;
	}

	if (utils_memory_are_equal(msg, dec, sizeof(msg)) == false)
	{
		hkdstest_print_line("hkds_katae_test: decrypted output does not match expected answer! -HKA4");
		res = false;
	}

	return res;
}

bool hkdstest_monte_carlo_test()
{
	/* protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication */
	const uint8_t PID = 0x10;
	/* master key id */
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device id						|		BKD ID			| PID | Mode		|	MID	   |			DID		   | */
	const uint8_t did[HKDS_DID_SIZE] = { 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
	uint8_t cpt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t dec[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	uint8_t exp[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t key[HKDS_BDK_SIZE] = { 0 };
	uint8_t msg[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t mres[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tokd[HKDS_STK_SIZE] = { 0 };
	uint8_t toke[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	bool res;

#if defined(HKDS_SHAKE_128)
	hkdstest_hex_to_bin("A2968FF59E0D700AD418EB0387D9F5E7", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", key, sizeof(key));
#elif defined(HKDS_SHAKE_256)
	hkdstest_hex_to_bin("5DA79EFD4C52DA29E08D14E05771130D", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
#else
	hkdstest_hex_to_bin("84827779CF9765C50DED4582B8384324", exp, sizeof(exp));
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key, sizeof(key));
#endif

	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));
	res = true;

	/* test master-key with known values */
	hkds_master_key mdk;
	memcpy(mdk.bdk, key, sizeof(key));
	memcpy(mdk.stk, key, sizeof(key));
	memcpy(mdk.kid, kid, sizeof(kid));

	/* generate the clients embedded key */
	hkds_server_generate_edk(mdk.bdk, did, edk);

	/* initialize the client */
	hkds_client_state cs;
	hkds_client_initialize_state(&cs, edk, did);

	hkds_server_state ss;

	for (size_t i = 0; i < HKDSTEST_CYCLES_COUNT; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state(&ss, &mdk, cs.ksn);

		if (i % HKDS_CACHE_SIZE == 0)
		{
			/* client requests the token key from server */
			hkds_server_encrypt_token(&ss, toke);

			/* client decrypts the token */
			if (hkds_client_decrypt_token(&cs, toke, tokd) == false)
			{
				hkdstest_print_line("monte_carlo_test: token authentication failure! -HMC1");
				res = false;
				break;
			}

			/* client derives the transaction key-set */
			hkds_client_generate_cache(&cs, tokd);
		}

		/* client encrypts a message */
		hkds_client_encrypt_message(&cs, msg, cpt);

		/* server decrypts the message */
		hkds_server_decrypt_message(&ss, cpt, dec);

		if (utils_memory_are_equal(msg, dec, sizeof(msg)) == false)
		{
			hkdstest_print_line("monte_carlo_test: decrypted output does not match expected answer! -HMC2");
			res = false;
			break;
		}

		for (size_t j = 0; j < HKDS_MESSAGE_SIZE; ++j)
		{
			mres[j] = mres[j] ^ cpt[j];
		}
	}

	if (utils_memory_are_equal(exp, mres, sizeof(exp)) == false)
	{
		hkdstest_print_line("monte_carlo_test: monte carlo output does not match expected answer! -HMC3");
		res = false;
	}

	return res;
}

bool hkdstest_stress_test()
{
	/* the PRF mode, 10 for SHAKE-256 */
	const uint8_t PRFMODE = 0x0A;
	/* protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication */
	const uint8_t PID = 0x10;
	/* master key id */
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device id						|		BKD ID			| PID | Mode |	MID	     |			DID		     | */
	const uint8_t did[HKDS_DID_SIZE] = { 0x01, 0x00, 0x00, 0x00, PID, PRFMODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
	uint8_t cpt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t dec[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	uint8_t msg[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tokd[HKDS_STK_SIZE] = { 0 };
	uint8_t toke[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	bool res;

	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));
	res = true;

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_master_key mdk;
	hkds_server_generate_mdk(&utils_seed_generate, &mdk, kid);

	/* generate the clients embedded key */
	hkds_server_generate_edk(mdk.bdk, did, edk);

	/* initialize the client */
	hkds_client_state cs;
	hkds_client_initialize_state(&cs, edk, did);

	hkds_server_state ss;

	for (size_t i = 0; i < HKDSTEST_CYCLES_COUNT; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state(&ss, &mdk, cs.ksn);

		if (i % HKDS_CACHE_SIZE == 0)
		{
			/* client requests the token key from server */
			hkds_server_encrypt_token(&ss, toke);

			/* client decrypts the token */
			if (hkds_client_decrypt_token(&cs, toke, tokd) == false)
			{
				hkdstest_print_line("hkds_stress_test: token authentication failure! -HST1");
				res = false;
				break;
			}

			/* client derives the transaction key-set */
			hkds_client_generate_cache(&cs, tokd);
		}

		/* client encrypts a message */
		hkds_client_encrypt_message(&cs, msg, cpt);

		/* server decrypts the message */
		hkds_server_decrypt_message(&ss, cpt, dec);

		if (utils_memory_are_equal(msg, dec, sizeof(msg)) == false)
		{
			hkdstest_print_line("hkds_stress_test: decrypted output does not match expected answer! -HST2");
			res = false;
			break;
		}
	}

	return res;
}

bool hkdstest_simd_encrypt_equivalence_test()
{
	const uint8_t PID = 0x10;
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device ids */
	const uint8_t didp[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE] = {
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00 }
	};

	uint8_t msgp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t cptp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp1[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp2[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edkp[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE] = { 0 };
	uint8_t tokdp[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE] = { 0 };
	uint8_t tokep1[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t tokep2[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t key[HKDS_BDK_SIZE] = { 0 };
	size_t i;
	bool res;

#if defined(HKDS_SHAKE_128)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", key, sizeof(key));
#elif defined(HKDS_SHAKE_256)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
#else
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key, sizeof(key));
#endif

	res = true;

	/* generate a set of random messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		utils_seed_generate(msgp[i], HKDS_MESSAGE_SIZE);
	}

	/* set a common master key */
	hkds_master_key mdk;
	memcpy(mdk.bdk, key, sizeof(key));
	memcpy(mdk.stk, key, sizeof(key));
	memcpy(mdk.kid, kid, sizeof(kid));

	/* generate the clients embedded keys */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_generate_edk(mdk.bdk, didp[i], edkp[i]);
	}

	/* initialize the client states */
	hkds_client_state csp[HKDS_CACHX8_DEPTH];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_initialize_state(&csp[i], edkp[i], didp[i]);
	}

	/* initialize the server with the client ksns */
	hkds_server_state ss[HKDS_CACHX8_DEPTH];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_initialize_state(&ss[i], &mdk, csp[i].ksn);
	}

	/* clients request the token keys from server */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_encrypt_token(&ss[i], tokep1[i]);
	}

	hkds_server_x8_state ssp;
	uint8_t ksnp[HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		memcpy(ksnp[i], csp[i].ksn, HKDS_KSN_SIZE);
	}

	hkds_server_initialize_state_x8(&ssp, &mdk, ksnp);
	hkds_server_encrypt_token_x8(&ssp, tokep2);

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(tokep1[i], tokep2[i], HKDS_STK_SIZE) == false)
		{
			hkdstest_print_line("hkds_parallel_encrypt_equivalence_test: parallel token encryption failure! -HSE1");
			res = false;
			break;
		}
	}

	/* clients decrypt the tokens */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_decrypt_token(&csp[i], tokep1[i], tokdp[i]);
	}

	/* clients derive the transaction key-sets */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_generate_cache(&csp[i], tokdp[i]);
	}

	/* clients encrypt messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_encrypt_message(&csp[i], msgp[i], cptp[i]);
	}

	/* server decrypts the messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_decrypt_message(&ss[i], cptp[i], decp1[i]);
	}

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(msgp[i], decp1[i], HKDS_MESSAGE_SIZE) == false)
		{
			hkdstest_print_line("hkds_parallel_encrypt_equivalence_test: sequential message decryption failure! -HSE2");
			res = false;
			break;
		}
	}

	hkds_server_decrypt_message_x8(&ssp, cptp, decp2);

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(msgp[i], decp2[i], HKDS_MESSAGE_SIZE) == false)
		{
			hkdstest_print_line("hkds_parallel_encrypt_equivalence_test: parallel message decryption failure! -HSE3");
			res = false;
			break;
		}
	}

	return res;
}

#if defined(SYSTEM_OPENMP)
bool hkdstest_parallel_encrypt_equivalence_test()
{
	const uint8_t PID = 0x10;
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };

	/* device ids */
	const uint8_t didp[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE] =
	{
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00 }
	};

	uint8_t msgp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t cpt1[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t cpt2[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp1[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp2[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edkp[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE] = { 0 };
	uint8_t tokdp[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE] = { 0 };
	uint8_t tokep1[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t tokep2[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t key[HKDS_BDK_SIZE] = { 0 };
	size_t i;
	size_t j;
	bool res;

#if defined(HKDS_SHAKE_128)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", key, sizeof(key));
#elif defined(HKDS_SHAKE_256)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
#else
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key, sizeof(key));
#endif

	res = true;

	/* generate a set of random messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		utils_seed_generate(msgp[i], HKDS_MESSAGE_SIZE);
	}

	/* set a common master key */
	hkds_master_key mdk = { 0 };
	memcpy(mdk.bdk, key, sizeof(key));
	memcpy(mdk.stk, key, sizeof(key));
	memcpy(mdk.kid, kid, sizeof(kid));

	/* generate the clients embedded keys */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_generate_edk(mdk.bdk, didp[i], edkp[i]);
	}

	/* initialize the client states */
	hkds_client_state csp[HKDS_CACHX8_DEPTH] = { 0 };

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_initialize_state(&csp[i], edkp[i], didp[i]);
	}

	/* initialize the server with the client ksns */
	hkds_server_state ss[HKDS_CACHX8_DEPTH] = { 0 };

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_initialize_state(&ss[i], &mdk, csp[i].ksn);
	}

	/* clients request the token keys from server */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_encrypt_token(&ss[i], tokep1[i]);
	}

	/* replicate the token keys in x64 */
	hkds_master_key mdkp[HKDS_PARALLEL_DEPTH] = { 0 };
	hkds_server_x8_state ssp[HKDS_PARALLEL_DEPTH] = { 0 };
	uint8_t ksnp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE] = { 0 };

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			memcpy(ksnp[i][j], csp[i].ksn, HKDS_KSN_SIZE);
		}

		memcpy(&mdkp[i], &mdk, sizeof(mdk));
	}

	hkds_server_initialize_state_x64(ssp, mdkp, ksnp);
	hkds_server_encrypt_token_x64(ssp, tokep2);

	/* compare the two sets of keys */

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			if (utils_memory_are_equal(tokep1[i], tokep2[i][j], HKDS_STK_SIZE) == false)
			{
				hkdstest_print_line("hkds_parallel_encrypt_equivalence_test: parallel token encryption failure! -HPE1");
				res = false;
				break;
			}
		}
	}

	/* clients decrypt the tokens */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (hkds_client_decrypt_token(&csp[i], tokep1[i], tokdp[i]) == false)
		{
			hkdstest_print_line("hkds_parallel_encrypt_equivalence_test: token authentication failure! -HPE2");
			res = false;
			break;
		}
	}

	/* clients derive the transaction key-sets */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_generate_cache(&csp[i], tokdp[i]);
	}

	/* clients encrypt messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_encrypt_message(&csp[i], msgp[i], cpt1[i]);
	}

	/* server decrypts the messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_decrypt_message(&ss[i], cpt1[i], decp1[i]);
	}

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(msgp[i], decp1[i], HKDS_MESSAGE_SIZE) == false)
		{
			hkdstest_print_line("hkds_parallel_encrypt_equivalence_test: sequential message decryption failure! -HPE3");
			res = false;
			break;
		}
	}

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			memcpy(cpt2[i][j], cpt1[i], HKDS_KSN_SIZE);
		}
	}

	hkds_server_decrypt_message_x64(ssp, cpt2, decp2);

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			if (utils_memory_are_equal(msgp[i], decp2[i][j], HKDS_MESSAGE_SIZE) == false)
			{
				hkdstest_print_line("hkds_parallel_encrypt_equivalence_test: parallel message decryption failure! -HPE4");
				res = false;
				break;
			}
		}
	}

	return res;
}
#endif

bool hkdstest_simd_authencrypt_equivalence_test()
{
	const uint8_t PID = 0x10;
	const uint8_t ad[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = {
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	};
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device ids */
	const uint8_t didp[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE] = {
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00 }
	};

	uint8_t msgp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t cptp[HKDS_CACHX8_DEPTH][HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp1[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp2[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edkp[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE] = { 0 };
	uint8_t tokdp[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE] = { 0 };
	uint8_t tokep1[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t tokep2[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t key[HKDS_BDK_SIZE] = { 0 };
	bool valid[HKDS_CACHX8_DEPTH];
	size_t i;
	bool res;

#if defined(HKDS_SHAKE_128)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", key, sizeof(key));
#elif defined(HKDS_SHAKE_256)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
#else
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key, sizeof(key));
#endif

	res = true;

	/* generate a set of random messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		utils_seed_generate(msgp[i], HKDS_MESSAGE_SIZE);
	}

	/* set a common master key */
	hkds_master_key mdk;
	memcpy(mdk.bdk, key, sizeof(key));
	memcpy(mdk.stk, key, sizeof(key));
	memcpy(mdk.kid, kid, sizeof(kid));

	/* generate the clients embedded keys */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_generate_edk(mdk.bdk, didp[i], edkp[i]);
	}

	/* initialize the client states */
	hkds_client_state csp[HKDS_CACHX8_DEPTH];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_initialize_state(&csp[i], edkp[i], didp[i]);
	}

	/* initialize the server with the client ksns */
	hkds_server_state ss[HKDS_CACHX8_DEPTH];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_initialize_state(&ss[i], &mdk, csp[i].ksn);
	}

	/* clients request the token keys from server */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_encrypt_token(&ss[i], tokep1[i]);
	}

	hkds_server_x8_state ssp;
	uint8_t ksnp[HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		memcpy(ksnp[i], csp[i].ksn, HKDS_KSN_SIZE);
	}

	hkds_server_initialize_state_x8(&ssp, &mdk, ksnp);
	hkds_server_encrypt_token_x8(&ssp, tokep2);

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(tokep1[i], tokep2[i], HKDS_STK_SIZE) == false)
		{
			hkdstest_print_line("hkds_simd_authencrypt_equivalence_test: parallel token encryption failure! -HSA1");
			res = false;
			break;
		}
	}

	/* clients decrypt the tokens */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (hkds_client_decrypt_token(&csp[i], tokep1[i], tokdp[i]) == false)
		{
			hkdstest_print_line("hkds_simd_authencrypt_equivalence_test: token authentication failure! -HSA2");
			res = false;
			break;
		}
	}

	/* clients derive the transaction key-sets */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_generate_cache(&csp[i], tokdp[i]);
	}

	/* clients encrypt messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_encrypt_authenticate_message(&csp[i], msgp[i], ad[i], HKDS_MESSAGE_SIZE, cptp[i]);
	}

	/* server decrypts the messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_decrypt_verify_message(&ss[i], cptp[i], ad[i], HKDS_MESSAGE_SIZE, decp1[i]);
	}

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(msgp[i], decp1[i], HKDS_MESSAGE_SIZE) == false)
		{
			hkdstest_print_line("hkds_simd_authencrypt_equivalence_test: sequential message decryption failure! -HSA3");
			res = false;
			break;
		}
	}

	hkds_server_decrypt_verify_message_x8(&ssp, cptp, ad, HKDS_MESSAGE_SIZE, decp2, valid);

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(msgp[i], decp2[i], HKDS_MESSAGE_SIZE) == false)
		{
			hkdstest_print_line("hkds_simd_authencrypt_equivalence_test: parallel message decryption failure! -HSA4");
			res = false;
			break;
		}

		if (valid[i] == false)
		{
			hkdstest_print_line("hkds_simd_authencrypt_equivalence_test: parallel message validity check failure! -HSA5");
			res = false;
			break;
		}
	}

	return res;
}

#if defined(SYSTEM_OPENMP)
bool hkdstest_parallel_authencrypt_equivalence_test()
{
	const uint8_t PID = 0x10;
	const uint8_t ad[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = {
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xC0, 0xA8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	};
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device ids */
	const uint8_t didp[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE] = {
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, PID, HKDSTEST_PRF_MODE, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00 }
	};

	uint8_t msgp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t cpt1[HKDS_CACHX8_DEPTH][HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t cpt2[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp1[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp2[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edkp[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE] = { 0 };
	uint8_t tokdp[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE] = { 0 };
	uint8_t tokep1[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t tokep2[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t key[HKDS_BDK_SIZE] = { 0 };
	bool valid[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH];
	size_t i;
	size_t j;
	bool res;

#if defined(HKDS_SHAKE_128)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", key, sizeof(key));
#elif defined(HKDS_SHAKE_256)
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
#else
	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key, sizeof(key));
#endif

	res = true;

	/* generate a set of random messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		utils_seed_generate(msgp[i], HKDS_MESSAGE_SIZE);
	}

	/* set a common master key */
	hkds_master_key mdk;
	memcpy(mdk.bdk, key, sizeof(key));
	memcpy(mdk.stk, key, sizeof(key));
	memcpy(mdk.kid, kid, sizeof(kid));

	/* generate the clients embedded keys */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_generate_edk(mdk.bdk, didp[i], edkp[i]);
	}

	/* initialize the client states */
	hkds_client_state csp[HKDS_CACHX8_DEPTH];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_initialize_state(&csp[i], edkp[i], didp[i]);
	}

	/* initialize the server with the client ksns */
	hkds_server_state ss[HKDS_CACHX8_DEPTH];

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_initialize_state(&ss[i], &mdk, csp[i].ksn);
	}

	/* clients request the token keys from server */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_encrypt_token(&ss[i], tokep1[i]);
	}

	hkds_master_key mdkp[HKDS_PARALLEL_DEPTH] = { 0 };
	hkds_server_x8_state ssp[HKDS_PARALLEL_DEPTH] = { 0 };
	uint8_t ksnp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE];

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			memcpy(ksnp[i][j], csp[i].ksn, HKDS_KSN_SIZE);
		}

		memcpy(&mdkp[i], &mdk, sizeof(mdk));
	}

	hkds_server_initialize_state_x64(ssp, mdkp, ksnp);
	hkds_server_encrypt_token_x64(ssp, tokep2);

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			if (utils_memory_are_equal(tokep1[i], tokep2[i][j], HKDS_STK_SIZE) == false)
			{
				hkdstest_print_line("hkds_parallel_authencrypt_equivalence_test: parallel token encryption failure! -HAE1");
				res = false;
				break;
			}
		}
	}

	/* clients decrypt the tokens */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (hkds_client_decrypt_token(&csp[i], tokep1[i], tokdp[i]) == false)
		{
			hkdstest_print_line("hkds_parallel_authencrypt_equivalence_test: token authentication failure! -HAE2");
			res = false;
			break;
		}
	}

	/* clients derive the transaction key-sets */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_generate_cache(&csp[i], tokdp[i]);
	}

	/* clients encrypt messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_client_encrypt_authenticate_message(&csp[i], msgp[i], ad[i], HKDS_MESSAGE_SIZE, cpt1[i]);
	}

	/* server decrypts the messages */
	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		hkds_server_decrypt_verify_message(&ss[i], cpt1[i], ad[i], HKDS_MESSAGE_SIZE, decp1[i]);
	}

	for (i = 0; i < HKDS_CACHX8_DEPTH; ++i)
	{
		if (utils_memory_are_equal(msgp[i], decp1[i], HKDS_MESSAGE_SIZE) == false)
		{
			hkdstest_print_line("hkds_parallel_authencrypt_equivalence_test: sequential message decryption failure! -HAE3");
			res = false;
			break;
		}
	}

	uint8_t adp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			memcpy(adp[i][j], ad[i], HKDS_MESSAGE_SIZE);
			memcpy(cpt2[i][j], cpt1[i], HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE);
		}
	}

	hkds_server_decrypt_verify_message_x64(ssp, cpt2, adp, HKDS_MESSAGE_SIZE, decp2, valid);

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		for (j = 0; j < HKDS_CACHX8_DEPTH; ++j)
		{
			if (utils_memory_are_equal(msgp[i], decp2[i][j], HKDS_MESSAGE_SIZE) == false)
			{
				hkdstest_print_line("hkds_parallel_authencrypt_equivalence_test: parallel message decryption failure! -HAE4");
				res = false;
				break;
			}

			if (valid[i][j] == false)
			{
				hkdstest_print_line("hkds_parallel_authencrypt_equivalence_test: parallel message validity check failure! -HAE5");
				res = false;
				break;
			}
		}
	}

	return res;
}
#endif

void hkdstest_test_run()
{
	if (hkdstest_kat_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS KAT test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS KAT test.");
	}

	if (hkdstest_katae_test() == true)
	{
		hkdstest_print_line("Success! Passed the authenticated HKDS KAT test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the authenticated HKDS KAT test.");
	}

	if (hkdstest_monte_carlo_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS monte carlo KAT test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS monte carlo KAT test.");
	}

	if (hkdstest_cycle_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS cycle test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS cycle test.");
	}

	if (hkdstest_stress_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS stress test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS stress test.");
	}

	if (hkdstest_simd_encrypt_equivalence_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS SIMD encryption equivalence test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS SIMD encryption equivalence test.");
	}

	if (hkdstest_simd_authencrypt_equivalence_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS SIMD authentication and encryption equivalence test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS SIMD authentication and encryption equivalence test.");
	}

#if defined(SYSTEM_OPENMP)

	if (hkdstest_parallel_encrypt_equivalence_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS parallel encryption equivalence test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS parallel encryption equivalence test.");
	}

	if (hkdstest_parallel_authencrypt_equivalence_test() == true)
	{
		hkdstest_print_line("Success! Passed the HKDS parallel authentication and encryption equivalence test.");
	}
	else
	{
		hkdstest_print_line("Failure! Failed the HKDS parallel authentication and encryption equivalence test.");
	}

#endif
}
