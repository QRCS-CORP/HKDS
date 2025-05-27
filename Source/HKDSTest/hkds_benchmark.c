#include "hkds_benchmark.h"
#include "testutils.h"
#include "../HKDS/hkds_client.h"
#include "../HKDS/keccak.h"
#include "../HKDS/hkds_server.h"
#include "../HKDS/utils.h"

/* bs*sc = 1GB */
#define BUFFER_SIZE 1024
#define SAMPLE_COUNT 1000000
#define ONE_GIGABYTE 1024000000
#define TEST_CYCLES 1000000

static void kmac128_benchmark(void)
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[16] = { 0 };
	uint8_t key[16] = { 0 };
	hkds_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	hkds_kmac_initialize(&ctx, HKDS_KECCAK_128_RATE, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		hkds_kmac_update(&ctx, HKDS_KECCAK_128_RATE, msg, sizeof(msg));
		hkds_kmac_finalize(&ctx, HKDS_KECCAK_128_RATE, tag, sizeof(tag));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-128 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void kmac256_benchmark(void)
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[32] = { 0 };
	uint8_t key[32] = { 0 };
	hkds_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	hkds_kmac_initialize(&ctx, HKDS_KECCAK_256_RATE, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		hkds_kmac_update(&ctx, HKDS_KECCAK_256_RATE, msg, sizeof(msg));
		hkds_kmac_finalize(&ctx, HKDS_KECCAK_256_RATE, tag, sizeof(tag));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-256 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void kmac512_benchmark(void)
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[64] = { 0 };
	uint8_t key[64] = { 0 };
	hkds_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	hkds_kmac_initialize(&ctx, HKDS_KECCAK_512_RATE, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		hkds_kmac_update(&ctx, HKDS_KECCAK_512_RATE, msg, sizeof(msg));
		hkds_kmac_finalize(&ctx, HKDS_KECCAK_512_RATE, tag, sizeof(tag));
		++tctr;
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-512 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

#if defined(SYSTEM_HAS_AVX2)
static void kmac128x4_benchmark(void)
{
	uint8_t msg[4][BUFFER_SIZE] = { 0 };
	uint8_t tag[4][16] = { 0 };
	uint8_t key[4][16] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_kmac_128x4(tag[0], tag[1], tag[2], tag[3], 16, key[0], key[1], key[2], key[3], 16,
			NULL, NULL, NULL, NULL, 0, msg[0], msg[1], msg[2], msg[3], BUFFER_SIZE);
		tctr += (4 * BUFFER_SIZE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-128x4 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void kmac256x4_benchmark(void)
{
	uint8_t msg[4][BUFFER_SIZE] = { 0 };
	uint8_t tag[4][32] = { 0 };
	uint8_t key[4][32] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_kmac_256x4(tag[0], tag[1], tag[2], tag[3], 32, key[0], key[1], key[2], key[3], 32,
			NULL, NULL, NULL, NULL, 0, msg[0], msg[1], msg[2], msg[3], BUFFER_SIZE);
		tctr += (4 * BUFFER_SIZE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-256x4 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void kmac512x4_benchmark(void)
{
	uint8_t msg[4][BUFFER_SIZE] = { 0 };
	uint8_t tag[4][64] = { 0 };
	uint8_t key[4][64] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_kmac_512x4(tag[0], tag[1], tag[2], tag[3], 64, key[0], key[1], key[2], key[3], 64,
			NULL, NULL, NULL, NULL, 0, msg[0], msg[1], msg[2], msg[3], BUFFER_SIZE);
		tctr += (4 * BUFFER_SIZE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-512x4 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}
#endif

#if defined(SYSTEM_HAS_AVX512)
static void kmac128x8_benchmark(void)
{
	uint8_t msg[8][BUFFER_SIZE] = { 0 };
	uint8_t tag[8][16] = { 0 };
	uint8_t key[8][16] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_kmac_128x8(tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7], 16,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 16,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0,
			msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], BUFFER_SIZE);
		tctr += (8 * BUFFER_SIZE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-128x8 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void kmac256x8_benchmark(void)
{
	uint8_t msg[8][BUFFER_SIZE] = { 0 };
	uint8_t tag[8][32] = { 0 };
	uint8_t key[8][32] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_kmac_256x8(tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7], 32,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 32,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0,
			msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], BUFFER_SIZE);
		tctr += (8 * BUFFER_SIZE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-256x8 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void kmac512x8_benchmark(void)
{
	uint8_t msg[8][BUFFER_SIZE] = { 0 };
	uint8_t tag[8][64] = { 0 };
	uint8_t key[8][64] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_kmac_512x8(tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7], 64,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 64,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0,
			msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], BUFFER_SIZE);
		tctr += (8 * BUFFER_SIZE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("KMAC-512x8 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}
#endif

static void shake128_benchmark(void)
{
	uint8_t key[16] = { 0 };
	uint8_t otp[HKDS_KECCAK_128_RATE] = { 0 };
	hkds_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_initialize(&ctx, hkds_keccak_rate_128, key, sizeof(key));
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_128, otp, 1);
		tctr += sizeof(otp);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-128 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void shake256_benchmark(void)
{
	uint8_t key[32] = { 0 };
	uint8_t otp[HKDS_KECCAK_256_RATE] = { 0 };
	hkds_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_initialize(&ctx, hkds_keccak_rate_256, key, sizeof(key));
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_256, otp, 1);
		tctr += sizeof(otp);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-256 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void shake512_benchmark(void)
{
	uint8_t key[64] = { 0 };
	uint8_t otp[HKDS_KECCAK_512_RATE] = { 0 };
	hkds_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_initialize(&ctx, hkds_keccak_rate_512, key, sizeof(key));
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_512, otp, 1);
		tctr += sizeof(otp);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-512 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

#if defined(SYSTEM_HAS_AVX2)
static void shake128x4_benchmark(void)
{
	uint8_t key[4][16] = { 0 };
	uint8_t otp[4][HKDS_KECCAK_128_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_128x4(otp[0], otp[1], otp[2], otp[3], HKDS_KECCAK_128_RATE, key[0], key[1], key[2], key[3], 16);
		tctr += (4 * HKDS_KECCAK_128_RATE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-128x4 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void shake256x4_benchmark(void)
{
	uint8_t key[4][32] = { 0 };
	uint8_t otp[4][HKDS_KECCAK_256_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_256x4(otp[0], otp[1], otp[2], otp[3], HKDS_KECCAK_256_RATE, key[0], key[1], key[2], key[3], 32);
		tctr += (4 * HKDS_KECCAK_256_RATE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-256x4 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void shake512x4_benchmark(void)
{
	uint8_t key[4][64] = { 0 };
	uint8_t otp[4][HKDS_KECCAK_512_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_512x4(otp[0], otp[1], otp[2], otp[3], HKDS_KECCAK_512_RATE, key[0], key[1], key[2], key[3], 64);
		tctr += (4 * HKDS_KECCAK_512_RATE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-512x4 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}
#endif

#if defined(SYSTEM_HAS_AVX512)
static void shake128x8_benchmark(void)
{
	uint8_t key[8][16] = { 0 };
	uint8_t otp[8][HKDS_KECCAK_128_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_128x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], HKDS_KECCAK_128_RATE,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 16);
		tctr += (8 * HKDS_KECCAK_128_RATE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-128x8 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void shake256x8_benchmark(void)
{
	uint8_t key[8][32] = { 0 };
	uint8_t otp[8][HKDS_KECCAK_256_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_256x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], HKDS_KECCAK_256_RATE,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 32);
		tctr += (8 * HKDS_KECCAK_256_RATE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-256x8 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void shake512x8_benchmark(void)
{
	uint8_t key[8][64] = { 0 };
	uint8_t otp[8][HKDS_KECCAK_512_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = utils_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		hkds_shake_512x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], HKDS_KECCAK_512_RATE,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 64);
		tctr += (8 * HKDS_KECCAK_512_RATE);
	}

	elapsed = utils_stopwatch_elapsed(start);
	hkdstest_print_safe("SHAKE-512x8 processed 1GB of data in ");
	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}
#endif

static void hkdstest_benchmark_client_encrypt_run(void)
{
#if defined(HKDS_SHAKE_128)
	/* the PRF mode, 9 for SHAKE-128 */
	const uint8_t PRFMODE = 0x09;
#elif defined(HKDS_SHAKE_256)
	/* the PRF mode, 10 for SHAKE-256 */
	const uint8_t PRFMODE = 0x0A;
#else
	/* the PRF mode, 11 for SHAKE-512 */
	const uint8_t PRFMODE = 0x0B;
#endif

	/* protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication */
	const uint8_t PID = 0x10;
	/* master key id */
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device id						|		BKD ID			| PID | Mode |	MID	   |			DID		   | */
	const uint8_t did[HKDS_DID_SIZE] = { 0x01, 0x00, 0x00, 0x00, PID, PRFMODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
	uint8_t cpt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	uint8_t msg[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tokd[HKDS_STK_SIZE] = { 0 };
	uint8_t toke[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint64_t start;
	uint64_t elapsed;

	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_master_key mdk;
	hkds_server_generate_mdk(&utils_seed_generate , &mdk, kid);

	/* generate the clients embedded key */
	hkds_server_generate_edk(mdk.bdk, did, edk);

	/* initialize the client */
	hkds_client_state cs;
	hkds_client_initialize_state(&cs, edk, did);

	start = utils_stopwatch_start();

	for (size_t i = 0; i < TEST_CYCLES; ++i)
	{
		if (i % HKDS_CACHE_SIZE == 0)
		{
			/* client decrypts the token */
			hkds_client_decrypt_token(&cs, toke, tokd);
			/* client derives the transaction key-set */
			hkds_client_generate_cache(&cs, tokd);
		}

		/* client encrypts a message */
		hkds_client_encrypt_message(&cs, msg, cpt);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 Client encrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 Client encrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 Client encrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void hkdstest_benchmark_client_encrypt_authenticate_run(void)
{
#if defined(HKDS_SHAKE_128)
	/* the PRF mode, 9 for SHAKE-128 */
	const uint8_t PRFMODE = 0x09;
#elif defined(HKDS_SHAKE_256)
	/* the PRF mode, 10 for SHAKE-256 */
	const uint8_t PRFMODE = 0x0A;
#else
	/* the PRF mode, 11 for SHAKE-512 */
	const uint8_t PRFMODE = 0x0B;
#endif

	/* protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication */
	const uint8_t PID = 0x10;
	/* master key id */
	const uint8_t ad[4] = { 0xC0, 0xA8, 0x00, 0x01 };
	/* master key id */
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	/* device id						|		BKD ID			| PID | Mode |	MID	   |			DID		   | */
	const uint8_t did[HKDS_DID_SIZE] = { 0x01, 0x00, 0x00, 0x00, PID, PRFMODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
	uint8_t cpt[HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t edk[HKDS_EDK_SIZE] = { 0 };
	uint8_t msg[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t tokd[HKDS_STK_SIZE] = { 0 };
	uint8_t toke[HKDS_STK_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint64_t start;
	uint64_t elapsed;

	hkdstest_hex_to_bin("000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_master_key mdk;
	hkds_server_generate_mdk(&utils_seed_generate , &mdk, kid);

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

	start = utils_stopwatch_start();

	for (size_t i = 0; i < TEST_CYCLES; ++i)
	{
		if (i % HKDS_CACHE_SIZE == 0)
		{
			/* client decrypts the token */
			hkds_client_decrypt_token(&cs, toke, tokd);
			/* client derives the transaction key-set */
			hkds_client_generate_cache(&cs, tokd);
		}

		/* client encrypts a message */
		hkds_client_encrypt_authenticate_message(&cs, msg, ad, sizeof(ad), cpt);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 Client authenticated and encrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 Client authenticated and encrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 Client authenticated and encrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void hkdstest_benchmark_server_decrypt_run(void)
{
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t cpt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t dec[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t ksn[HKDS_MESSAGE_SIZE] = { 0 };
	hkds_master_key mdk = { 0 };
	hkds_server_state ss = { 0 };
	uint64_t start;
	uint64_t elapsed;

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_server_generate_mdk(&utils_seed_generate, &mdk, kid);

	start = utils_stopwatch_start();

	for (size_t i = 0; i < TEST_CYCLES; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state(&ss, &mdk, ksn);
		/* server decrypts the message */
		hkds_server_decrypt_message(&ss, cpt, dec);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 Server decrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 Server decrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 Server decrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void hkdstest_benchmark_server_decrypt_authenticate_run(void)
{
	const uint8_t ad[4] = { 0xC0, 0xA8, 0x00, 0x01 };
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t cpt[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t dec[HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t ksn[HKDS_KSN_SIZE] = { 0 };
	hkds_master_key mdk = { 0 };
	hkds_server_state ss = { 0 };
	uint64_t start;
	uint64_t elapsed;

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_server_generate_mdk(&utils_seed_generate, &mdk, kid);

	start = utils_stopwatch_start();

	for (size_t i = 0; i < TEST_CYCLES; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state(&ss, &mdk, ksn);
		/* server decrypts the message */
		hkds_server_decrypt_verify_message(&ss, cpt, ad, sizeof(ad), dec);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 Server authenticated and decrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 Server authenticated and decrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 Server authenticated and decrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void hkdstest_benchmark_server_decrypt_x8_run(void)
{
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t cptp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t ksnp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	hkds_master_key mdk = { 0 };
	hkds_server_x8_state ssp = { 0 };
	uint64_t start;
	uint64_t elapsed;

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_server_generate_mdk(&utils_seed_generate, &mdk, kid);

	start = utils_stopwatch_start();

	for (size_t i = 0; i < TEST_CYCLES / HKDS_CACHX8_DEPTH; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state_x8(&ssp, &mdk, ksnp);
		/* server decrypts the message */
		hkds_server_decrypt_message_x8(&ssp, cptp, decp);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 SIMD Server decrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 SIMD Server decrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 SIMD Server decrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void hkdstest_benchmark_server_decrypt_authenticate_x8_run(void)
{
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t cptp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t data[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t ksnp[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	bool valid[HKDS_CACHX8_DEPTH] = { false };
	hkds_master_key mdk = { 0 };
	hkds_server_x8_state ssp = { 0 };
	uint64_t start;
	uint64_t elapsed;

	/* generate the master derivation key {BDK, BTK, MID} */
	hkds_server_generate_mdk(&utils_seed_generate, &mdk, kid);

	start = utils_stopwatch_start();

	for (size_t i = 0; i < TEST_CYCLES / HKDS_CACHX8_DEPTH; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state_x8(&ssp, &mdk, ksnp);
		/* server decrypts the message */
		hkds_server_decrypt_verify_message_x8(&ssp, cptp, data, HKDS_MESSAGE_SIZE, decp, valid);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 SIMD Server authenticated and decrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 SIMD Server authenticated and decrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 SIMD Server authenticated and decrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

#if defined(SYSTEM_OPENMP)
static void hkdstest_benchmark_server_decrypt_x64_run(void)
{
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t cptp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t ksnp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE] = { 0 };
	hkds_master_key mdk[HKDS_PARALLEL_DEPTH] = { 0 };
	hkds_server_x8_state ssp[HKDS_PARALLEL_DEPTH] = { 0 };
	uint64_t start;
	uint64_t elapsed;
	size_t i;

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		hkds_server_generate_mdk(&utils_seed_generate, &mdk[i], kid);
	}

	hkds_server_initialize_state_x64(ssp, mdk, ksnp);

	start = utils_stopwatch_start();

	for (i = 0; i < TEST_CYCLES / HKDS_CACHX64_SIZE; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state_x64(ssp, mdk, ksnp);
		/* server decrypts the message */
		hkds_server_decrypt_message_x64(ssp, cptp, decp);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 Parallel SIMD Server decrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 Parallel SIMD Server decrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 Parallel SIMD Server decrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}

static void hkdstest_benchmark_server_decrypt_authenticate_x64_run(void)
{
	const uint8_t kid[HKDS_KID_SIZE] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t cptp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE] = { 0 };
	uint8_t data[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t decp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE] = { 0 };
	uint8_t ksnp[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE] = { 0 };
	bool valid[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH] = { false };
	hkds_master_key mdk[HKDS_PARALLEL_DEPTH] = { 0 };
	hkds_server_x8_state ssp[HKDS_PARALLEL_DEPTH] = { 0 };
	uint64_t start;
	uint64_t elapsed;
	size_t i;

	for (i = 0; i < HKDS_PARALLEL_DEPTH; ++i)
	{
		hkds_server_generate_mdk(&utils_seed_generate, &mdk[i], kid);
	}

	hkds_server_initialize_state_x64(ssp, mdk, ksnp);

	start = utils_stopwatch_start();

	for (i = 0; i < TEST_CYCLES / HKDS_CACHX64_SIZE; ++i)
	{
		/* initialize the server with the client-ksn */
		hkds_server_initialize_state_x64(ssp, mdk, ksnp);
		/* server decrypts the message */
		hkds_server_decrypt_verify_message_x64(ssp, cptp, data, HKDS_MESSAGE_SIZE, decp, valid);
	}

	elapsed = utils_stopwatch_elapsed(start);

#if defined(HKDS_SHAKE_128)
	hkdstest_print_safe("HKDS-128 Parallel SIMD Server authenticated and decrypted 1 million messages in ");
#elif defined(HKDS_SHAKE_256)
	hkdstest_print_safe("HKDS-256 Parallel SIMD Server authenticated and decrypted 1 million messages in ");
#else
	hkdstest_print_safe("HKDS-512 Parallel SIMD Server authenticated and decrypted 1 million messages in ");
#endif

	hkdstest_print_double((double)elapsed / 1000.0);
	hkdstest_print_line(" seconds");
}
#endif

void hkdstest_benchmark_hkds_server_run()
{
	hkdstest_benchmark_server_decrypt_run();
	hkdstest_benchmark_server_decrypt_x8_run();
#if defined(SYSTEM_OPENMP)
	hkdstest_benchmark_server_decrypt_x64_run();
#endif
	hkdstest_benchmark_server_decrypt_authenticate_run();
	hkdstest_benchmark_server_decrypt_authenticate_x8_run();
#if defined(SYSTEM_OPENMP)
	hkdstest_benchmark_server_decrypt_authenticate_x64_run();
#endif
}

void hkdstest_benchmark_hkds_client_run()
{
	hkdstest_benchmark_client_encrypt_run();
	hkdstest_benchmark_client_encrypt_authenticate_run();
}

void hkdstest_benchmark_kmac_run()
{
	hkdstest_print_line("Running the KMAC-128 performance benchmarks.");
	kmac128_benchmark();

	hkdstest_print_line("Running the KMAC-256 performance benchmarks.");
	kmac256_benchmark();

	hkdstest_print_line("Running the KMAC-512 performance benchmarks.");
	kmac512_benchmark();

#if defined(SYSTEM_HAS_AVX2)
	hkdstest_print_line("Running the AVX2 4X KMAC-128 performance benchmarks.");
	kmac128x4_benchmark();

	hkdstest_print_line("Running the AVX2 4X KMAC-256 performance benchmarks.");
	kmac256x4_benchmark();

	hkdstest_print_line("Running the AVX2 4X KMAC-512 performance benchmarks.");
	kmac512x4_benchmark();
#endif

#if defined(SYSTEM_HAS_AVX512)
	hkdstest_print_line("Running the AVX512 8X KMAC-128 performance benchmarks.");
	kmac128x8_benchmark();

	hkdstest_print_line("Running the AVX512 8X KMAC-256 performance benchmarks.");
	kmac256x8_benchmark();

	hkdstest_print_line("Running the AVX512 8X KMAC-512 performance benchmarks.");
	kmac512x8_benchmark();
#endif
}

void hkdstest_benchmark_shake_run()
{
	hkdstest_print_line("Running the SHAKE-128 performance benchmarks.");
	shake128_benchmark();

	hkdstest_print_line("Running the SHAKE-256 performance benchmarks.");
	shake256_benchmark();

	hkdstest_print_line("Running the SHAKE-512 performance benchmarks.");
	shake512_benchmark();

#if defined(SYSTEM_HAS_AVX2)
	hkdstest_print_line("Running the AVX2 4X SHAKE-128 performance benchmarks.");
	shake128x4_benchmark();

	hkdstest_print_line("Running the AVX2 4X SHAKE-256 performance benchmarks.");
	shake256x4_benchmark();

	hkdstest_print_line("Running the AVX2 4X SHAKE-512 performance benchmarks.");
	shake512x4_benchmark();
#endif

#if defined(SYSTEM_HAS_AVX512)
	hkdstest_print_line("Running the AVX512 8X SHAKE-128 performance benchmarks.");
	shake128x8_benchmark();

	hkdstest_print_line("Running the AVX512 8X SHAKE-256 performance benchmarks.");
	shake256x8_benchmark();

	hkdstest_print_line("Running the AVX512 8X SHAKE-512 performance benchmarks.");
	shake512x8_benchmark();
#endif
}

