#include "keccak.h"
#include "utils.h"

#define KPA_LEAF_HASH128 16
#define KPA_LEAF_HASH256 32
#define KPA_LEAF_HASH512 64

/* keccak round constants */
static const uint64_t KECCAK_ROUND_CONSTANTS[HKDS_KECCAK_PERMUTATION_MAX_ROUNDS] =
{
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
	0x8000000080008082ULL, 0x800000008000800AULL, 0x8000000000000003ULL, 0x8000000080000009ULL,
	0x8000000000008082ULL, 0x0000000000008009ULL, 0x8000000000000080ULL, 0x0000000000008083ULL,
	0x8000000000000081ULL, 0x0000000000000001ULL, 0x000000000000800BULL, 0x8000000080008001ULL,
	0x0000000000000080ULL, 0x8000000000008000ULL, 0x8000000080008001ULL, 0x0000000000000009ULL,
	0x800000008000808BULL, 0x0000000000000081ULL, 0x8000000000000082ULL, 0x000000008000008BULL,
	0x8000000080008009ULL, 0x8000000080000000ULL, 0x0000000080000080ULL, 0x0000000080008003ULL
};

/* Common */

static void keccak_fast_absorb(uint64_t* state, const uint8_t* message, size_t msglen)
{
#if defined(SYSTEM_IS_LITTLE_ENDIAN)
	utils_memory_xor((uint8_t*)state, message, msglen);
#else
	for (size_t i = 0; i < msglen / sizeof(uint64_t); ++i)
	{
		state[i] ^= utils_integer_le8to64((message + (sizeof(uint64_t) * i)));
	}
#endif
}

static size_t keccak_left_encode(uint8_t* buffer, size_t value)
{
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && n < sizeof(size_t); ++n, v >>= 8) { /* increments n */ }

	if (n == 0)
	{
		n = 1;
	}

	for (size_t i = 1; i <= n; ++i)
	{
		buffer[i] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[0] = (uint8_t)n;

	return n + 1;
}

static size_t keccak_right_encode(uint8_t* buffer, size_t value)
{
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) { /* increments n */ }

	if (n == 0)
	{
		n = 1;
	}

	for (size_t i = 1; i <= n; ++i)
	{
		buffer[i - 1] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[n] = (uint8_t)n;

	return n + 1;
}

#if defined(SYSTEM_HAS_AVX512)
#	if defined(HKDS_KECCAK_UNROLLED_PERMUTATION)

void hkds_keccak_permute_p8x1600(__m512i state[HKDS_KECCAK_STATE_SIZE], size_t rounds)
{
	assert(rounds % 2 == 0);

	__m512i a0;
	__m512i a1;
	__m512i a2;
	__m512i a3;
	__m512i a4;
	__m512i a5;
	__m512i a6;
	__m512i a7;
	__m512i a8;
	__m512i a9;
	__m512i a10;
	__m512i a11;
	__m512i a12;
	__m512i a13;
	__m512i a14;
	__m512i a15;
	__m512i a16;
	__m512i a17;
	__m512i a18;
	__m512i a19;
	__m512i a20;
	__m512i a21;
	__m512i a22;
	__m512i a23;
	__m512i a24;
	__m512i c0;
	__m512i c1;
	__m512i c2;
	__m512i c3;
	__m512i c4;
	__m512i d0;
	__m512i d1;
	__m512i d2;
	__m512i d3;
	__m512i d4;
	__m512i e0;
	__m512i e1;
	__m512i e2;
	__m512i e3;
	__m512i e4;
	__m512i e5;
	__m512i e6;
	__m512i e7;
	__m512i e8;
	__m512i e9;
	__m512i e10;
	__m512i e11;
	__m512i e12;
	__m512i e13;
	__m512i e14;
	__m512i e15;
	__m512i e16;
	__m512i e17;
	__m512i e18;
	__m512i e19;
	__m512i e20;
	__m512i e21;
	__m512i e22;
	__m512i e23;
	__m512i e24;
	size_t i;

	a0 = state[0];
	a1 = state[1];
	a2 = state[2];
	a3 = state[3];
	a4 = state[4];
	a5 = state[5];
	a6 = state[6];
	a7 = state[7];
	a8 = state[8];
	a9 = state[9];
	a10 = state[10];
	a11 = state[11];
	a12 = state[12];
	a13 = state[13];
	a14 = state[14];
	a15 = state[15];
	a16 = state[16];
	a17 = state[17];
	a18 = state[18];
	a19 = state[19];
	a20 = state[20];
	a21 = state[21];
	a22 = state[22];
	a23 = state[23];
	a24 = state[24];

	for (i = 0; i < rounds; i += 2)
	{
		/* round n */
		c0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a0, a5), _mm512_xor_si512(a10, a15)), a20);
		c1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a1, a6), _mm512_xor_si512(a11, a16)), a21);
		c2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a2, a7), _mm512_xor_si512(a12, a17)), a22);
		c3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a3, a8), _mm512_xor_si512(a13, a18)), a23);
		c4 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a4, a9), _mm512_xor_si512(a14, a19)), a24);
		d0 = _mm512_xor_si512(c4, _mm512_or_si512(_mm512_slli_epi64(c1, 1), _mm512_srli_epi64(c1, 64 - 1)));
		d1 = _mm512_xor_si512(c0, _mm512_or_si512(_mm512_slli_epi64(c2, 1), _mm512_srli_epi64(c2, 64 - 1)));
		d2 = _mm512_xor_si512(c1, _mm512_or_si512(_mm512_slli_epi64(c3, 1), _mm512_srli_epi64(c3, 64 - 1)));
		d3 = _mm512_xor_si512(c2, _mm512_or_si512(_mm512_slli_epi64(c4, 1), _mm512_srli_epi64(c4, 64 - 1)));
		d4 = _mm512_xor_si512(c3, _mm512_or_si512(_mm512_slli_epi64(c0, 1), _mm512_srli_epi64(c0, 64 - 1)));
		a0 = _mm512_xor_si512(a0, d0);
		c0 = a0;
		a6 = _mm512_xor_si512(a6, d1);
		c1 = _mm512_or_si512(_mm512_slli_epi64(a6, 44), _mm512_srli_epi64(a6, 64 - 44));
		a12 = _mm512_xor_si512(a12, d2);
		c2 = _mm512_or_si512(_mm512_slli_epi64(a12, 43), _mm512_srli_epi64(a12, 64 - 43));
		a18 = _mm512_xor_si512(a18, d3);
		c3 = _mm512_or_si512(_mm512_slli_epi64(a18, 21), _mm512_srli_epi64(a18, 64 - 21));
		a24 = _mm512_xor_si512(a24, d4);
		c4 = _mm512_or_si512(_mm512_slli_epi64(a24, 14), _mm512_srli_epi64(a24, 64 - 14));
		e0 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		e0 = _mm512_xor_si512(e0, _mm512_set1_epi64(KECCAK_ROUND_CONSTANTS[i]));
		e1 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		e2 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		e3 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		e4 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		a3 = _mm512_xor_si512(a3, d3);
		c0 = _mm512_or_si512(_mm512_slli_epi64(a3, 28), _mm512_srli_epi64(a3, 64 - 28));
		a9 = _mm512_xor_si512(a9, d4);
		c1 = _mm512_or_si512(_mm512_slli_epi64(a9, 20), _mm512_srli_epi64(a9, 64 - 20));
		a10 = _mm512_xor_si512(a10, d0);
		c2 = _mm512_or_si512(_mm512_slli_epi64(a10, 3), _mm512_srli_epi64(a10, 64 - 3));
		a16 = _mm512_xor_si512(a16, d1);
		c3 = _mm512_or_si512(_mm512_slli_epi64(a16, 45), _mm512_srli_epi64(a16, 64 - 45));
		a22 = _mm512_xor_si512(a22, d2);
		c4 = _mm512_or_si512(_mm512_slli_epi64(a22, 61), _mm512_srli_epi64(a22, 64 - 61));
		e5 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		e6 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		e7 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		e8 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		e9 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		a1 = _mm512_xor_si512(a1, d1);
		c0 = _mm512_or_si512(_mm512_slli_epi64(a1, 1), _mm512_srli_epi64(a1, 64 - 1));
		a7 = _mm512_xor_si512(a7, d2);
		c1 = _mm512_or_si512(_mm512_slli_epi64(a7, 6), _mm512_srli_epi64(a7, 64 - 6));
		a13 = _mm512_xor_si512(a13, d3);
		c2 = _mm512_or_si512(_mm512_slli_epi64(a13, 25), _mm512_srli_epi64(a13, 64 - 25));
		a19 = _mm512_xor_si512(a19, d4);
		c3 = _mm512_or_si512(_mm512_slli_epi64(a19, 8), _mm512_srli_epi64(a19, 64 - 8));
		a20 = _mm512_xor_si512(a20, d0);
		c4 = _mm512_or_si512(_mm512_slli_epi64(a20, 18), _mm512_srli_epi64(a20, 64 - 18));
		e10 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		e11 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		e12 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		e13 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		e14 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		a4 = _mm512_xor_si512(a4, d4);
		c0 = _mm512_or_si512(_mm512_slli_epi64(a4, 27), _mm512_srli_epi64(a4, 64 - 27));
		a5 = _mm512_xor_si512(a5, d0);
		c1 = _mm512_or_si512(_mm512_slli_epi64(a5, 36), _mm512_srli_epi64(a5, 64 - 36));
		a11 = _mm512_xor_si512(a11, d1);
		c2 = _mm512_or_si512(_mm512_slli_epi64(a11, 10), _mm512_srli_epi64(a11, 64 - 10));
		a17 = _mm512_xor_si512(a17, d2);
		c3 = _mm512_or_si512(_mm512_slli_epi64(a17, 15), _mm512_srli_epi64(a17, 64 - 15));
		a23 = _mm512_xor_si512(a23, d3);
		c4 = _mm512_or_si512(_mm512_slli_epi64(a23, 56), _mm512_srli_epi64(a23, 64 - 56));
		e15 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		e16 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		e17 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		e18 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		e19 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		a2 = _mm512_xor_si512(a2, d2);
		c0 = _mm512_or_si512(_mm512_slli_epi64(a2, 62), _mm512_srli_epi64(a2, 64 - 62));
		a8 = _mm512_xor_si512(a8, d3);
		c1 = _mm512_or_si512(_mm512_slli_epi64(a8, 55), _mm512_srli_epi64(a8, 64 - 55));
		a14 = _mm512_xor_si512(a14, d4);
		c2 = _mm512_or_si512(_mm512_slli_epi64(a14, 39), _mm512_srli_epi64(a14, 64 - 39));
		a15 = _mm512_xor_si512(a15, d0);
		c3 = _mm512_or_si512(_mm512_slli_epi64(a15, 41), _mm512_srli_epi64(a15, 64 - 41));
		a21 = _mm512_xor_si512(a21, d1);
		c4 = _mm512_or_si512(_mm512_slli_epi64(a21, 2), _mm512_srli_epi64(a21, 64 - 2));
		e20 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		e21 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		e22 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		e23 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		e24 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		/* round n + 1 */
		c0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e0, e5), _mm512_xor_si512(e10, e15)), e20);
		c1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e1, e6), _mm512_xor_si512(e11, e16)), e21);
		c2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e2, e7), _mm512_xor_si512(e12, e17)), e22);
		c3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e3, e8), _mm512_xor_si512(e13, e18)), e23);
		c4 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e4, e9), _mm512_xor_si512(e14, e19)), e24);
		d0 = _mm512_xor_si512(c4, _mm512_or_si512(_mm512_slli_epi64(c1, 1), _mm512_srli_epi64(c1, 64 - 1)));
		d1 = _mm512_xor_si512(c0, _mm512_or_si512(_mm512_slli_epi64(c2, 1), _mm512_srli_epi64(c2, 64 - 1)));
		d2 = _mm512_xor_si512(c1, _mm512_or_si512(_mm512_slli_epi64(c3, 1), _mm512_srli_epi64(c3, 64 - 1)));
		d3 = _mm512_xor_si512(c2, _mm512_or_si512(_mm512_slli_epi64(c4, 1), _mm512_srli_epi64(c4, 64 - 1)));
		d4 = _mm512_xor_si512(c3, _mm512_or_si512(_mm512_slli_epi64(c0, 1), _mm512_srli_epi64(c0, 64 - 1)));
		e0 = _mm512_xor_si512(e0, d0);
		c0 = e0;
		e6 = _mm512_xor_si512(e6, d1);
		c1 = _mm512_or_si512(_mm512_slli_epi64(e6, 44), _mm512_srli_epi64(e6, 64 - 44));
		e12 = _mm512_xor_si512(e12, d2);
		c2 = _mm512_or_si512(_mm512_slli_epi64(e12, 43), _mm512_srli_epi64(e12, 64 - 43));
		e18 = _mm512_xor_si512(e18, d3);
		c3 = _mm512_or_si512(_mm512_slli_epi64(e18, 21), _mm512_srli_epi64(e18, 64 - 21));
		e24 = _mm512_xor_si512(e24, d4);
		c4 = _mm512_or_si512(_mm512_slli_epi64(e24, 14), _mm512_srli_epi64(e24, 64 - 14));
		a0 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		a0 = _mm512_xor_si512(a0, _mm512_set1_epi64(KECCAK_ROUND_CONSTANTS[i + 1]));
		a1 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		a2 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		a3 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		a4 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		e3 = _mm512_xor_si512(e3, d3);
		c0 = _mm512_or_si512(_mm512_slli_epi64(e3, 28), _mm512_srli_epi64(e3, 64 - 28));
		e9 = _mm512_xor_si512(e9, d4);
		c1 = _mm512_or_si512(_mm512_slli_epi64(e9, 20), _mm512_srli_epi64(e9, 64 - 20));
		e10 = _mm512_xor_si512(e10, d0);
		c2 = _mm512_or_si512(_mm512_slli_epi64(e10, 3), _mm512_srli_epi64(e10, 64 - 3));
		e16 = _mm512_xor_si512(e16, d1);
		c3 = _mm512_or_si512(_mm512_slli_epi64(e16, 45), _mm512_srli_epi64(e16, 64 - 45));
		e22 = _mm512_xor_si512(e22, d2);
		c4 = _mm512_or_si512(_mm512_slli_epi64(e22, 61), _mm512_srli_epi64(e22, 64 - 61));
		a5 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		a6 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		a7 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		a8 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		a9 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		e1 = _mm512_xor_si512(e1, d1);
		c0 = _mm512_or_si512(_mm512_slli_epi64(e1, 1), _mm512_srli_epi64(e1, 64 - 1));
		e7 = _mm512_xor_si512(e7, d2);
		c1 = _mm512_or_si512(_mm512_slli_epi64(e7, 6), _mm512_srli_epi64(e7, 64 - 6));
		e13 = _mm512_xor_si512(e13, d3);
		c2 = _mm512_or_si512(_mm512_slli_epi64(e13, 25), _mm512_srli_epi64(e13, 64 - 25));
		e19 = _mm512_xor_si512(e19, d4);
		c3 = _mm512_or_si512(_mm512_slli_epi64(e19, 8), _mm512_srli_epi64(e19, 64 - 8));
		e20 = _mm512_xor_si512(e20, d0);
		c4 = _mm512_or_si512(_mm512_slli_epi64(e20, 18), _mm512_srli_epi64(e20, 64 - 18));
		a10 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		a11 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		a12 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		a13 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		a14 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		e4 = _mm512_xor_si512(e4, d4);
		c0 = _mm512_or_si512(_mm512_slli_epi64(e4, 27), _mm512_srli_epi64(e4, 64 - 27));
		e5 = _mm512_xor_si512(e5, d0);
		c1 = _mm512_or_si512(_mm512_slli_epi64(e5, 36), _mm512_srli_epi64(e5, 64 - 36));
		e11 = _mm512_xor_si512(e11, d1);
		c2 = _mm512_or_si512(_mm512_slli_epi64(e11, 10), _mm512_srli_epi64(e11, 64 - 10));
		e17 = _mm512_xor_si512(e17, d2);
		c3 = _mm512_or_si512(_mm512_slli_epi64(e17, 15), _mm512_srli_epi64(e17, 64 - 15));
		e23 = _mm512_xor_si512(e23, d3);
		c4 = _mm512_or_si512(_mm512_slli_epi64(e23, 56), _mm512_srli_epi64(e23, 64 - 56));
		a15 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		a16 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		a17 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		a18 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		a19 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
		e2 = _mm512_xor_si512(e2, d2);
		c0 = _mm512_or_si512(_mm512_slli_epi64(e2, 62), _mm512_srli_epi64(e2, 64 - 62));
		e8 = _mm512_xor_si512(e8, d3);
		c1 = _mm512_or_si512(_mm512_slli_epi64(e8, 55), _mm512_srli_epi64(e8, 64 - 55));
		e14 = _mm512_xor_si512(e14, d4);
		c2 = _mm512_or_si512(_mm512_slli_epi64(e14, 39), _mm512_srli_epi64(e14, 64 - 39));
		e15 = _mm512_xor_si512(e15, d0);
		c3 = _mm512_or_si512(_mm512_slli_epi64(e15, 41), _mm512_srli_epi64(e15, 64 - 41));
		e21 = _mm512_xor_si512(e21, d1);
		c4 = _mm512_or_si512(_mm512_slli_epi64(e21, 2), _mm512_srli_epi64(e21, 64 - 2));
		a20 = _mm512_xor_si512(c0, _mm512_and_si512(_mm512_xor_epi64(c1, _mm512_set1_epi64(-1)), c2));
		a21 = _mm512_xor_si512(c1, _mm512_and_si512(_mm512_xor_epi64(c2, _mm512_set1_epi64(-1)), c3));
		a22 = _mm512_xor_si512(c2, _mm512_and_si512(_mm512_xor_epi64(c3, _mm512_set1_epi64(-1)), c4));
		a23 = _mm512_xor_si512(c3, _mm512_and_si512(_mm512_xor_epi64(c4, _mm512_set1_epi64(-1)), c0));
		a24 = _mm512_xor_si512(c4, _mm512_and_si512(_mm512_xor_epi64(c0, _mm512_set1_epi64(-1)), c1));
	}

	state[0] = a0;
	state[1] = a1;
	state[2] = a2;
	state[3] = a3;
	state[4] = a4;
	state[5] = a5;
	state[6] = a6;
	state[7] = a7;
	state[8] = a8;
	state[9] = a9;
	state[10] = a10;
	state[11] = a11;
	state[12] = a12;
	state[13] = a13;
	state[14] = a14;
	state[15] = a15;
	state[16] = a16;
	state[17] = a17;
	state[18] = a18;
	state[19] = a19;
	state[20] = a20;
	state[21] = a21;
	state[22] = a22;
	state[23] = a23;
	state[24] = a24;
}

#	else

void hkds_keccak_permute_p8x1600(__m512i state[HKDS_KECCAK_STATE_SIZE], size_t rounds)
{
	assert(rounds % 2 == 0);

	__m512i a[25] = { 0 };
	__m512i c[5] = { 0 };
	__m512i d[5] = { 0 };
	__m512i e[25] = { 0 };
	size_t i;

	for (i = 0; i < HKDS_KECCAK_STATE_SIZE; ++i)
	{
		a[i] = state[i];
	}

	for (i = 0; i < rounds; i += 2)
	{
		/* round n */
		c[0] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[0], a[5]), _mm512_xor_si512(a[10], a[15])), a[20]);
		c[1] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[1], a[6]), _mm512_xor_si512(a[11], a[16])), a[21]);
		c[2] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[2], a[7]), _mm512_xor_si512(a[12], a[17])), a[22]);
		c[3] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[3], a[8]), _mm512_xor_si512(a[13], a[18])), a[23]);
		c[4] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[4], a[9]), _mm512_xor_si512(a[14], a[19])), a[24]);
		d[0] = _mm512_xor_si512(c[4], _mm512_or_si512(_mm512_slli_epi64(c[1], 1), _mm512_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm512_xor_si512(c[0], _mm512_or_si512(_mm512_slli_epi64(c[2], 1), _mm512_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm512_xor_si512(c[1], _mm512_or_si512(_mm512_slli_epi64(c[3], 1), _mm512_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm512_xor_si512(c[2], _mm512_or_si512(_mm512_slli_epi64(c[4], 1), _mm512_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm512_xor_si512(c[3], _mm512_or_si512(_mm512_slli_epi64(c[0], 1), _mm512_srli_epi64(c[0], 64 - 1)));
		a[0] = _mm512_xor_si512(a[0], d[0]);
		c[0] = a[0];
		a[6] = _mm512_xor_si512(a[6], d[1]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[6], 44), _mm512_srli_epi64(a[6], 64 - 44));
		a[12] = _mm512_xor_si512(a[12], d[2]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[12], 43), _mm512_srli_epi64(a[12], 64 - 43));
		a[18] = _mm512_xor_si512(a[18], d[3]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[18], 21), _mm512_srli_epi64(a[18], 64 - 21));
		a[24] = _mm512_xor_si512(a[24], d[4]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[24], 14), _mm512_srli_epi64(a[24], 64 - 14));
		e[0] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[0] = _mm512_xor_si512(e[0], _mm512_set1_epi64(KECCAK_ROUND_CONSTANTS[i]));
		e[1] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[2] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[3] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[4] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[3] = _mm512_xor_si512(a[3], d[3]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[3], 28), _mm512_srli_epi64(a[3], 64 - 28));
		a[9] = _mm512_xor_si512(a[9], d[4]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[9], 20), _mm512_srli_epi64(a[9], 64 - 20));
		a[10] = _mm512_xor_si512(a[10], d[0]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[10], 3), _mm512_srli_epi64(a[10], 64 - 3));
		a[16] = _mm512_xor_si512(a[16], d[1]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[16], 45), _mm512_srli_epi64(a[16], 64 - 45));
		a[22] = _mm512_xor_si512(a[22], d[2]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[22], 61), _mm512_srli_epi64(a[22], 64 - 61));
		e[5] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[6] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[7] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[8] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[9] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[1] = _mm512_xor_si512(a[1], d[1]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[1], 1), _mm512_srli_epi64(a[1], 64 - 1));
		a[7] = _mm512_xor_si512(a[7], d[2]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[7], 6), _mm512_srli_epi64(a[7], 64 - 6));
		a[13] = _mm512_xor_si512(a[13], d[3]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[13], 25), _mm512_srli_epi64(a[13], 64 - 25));
		a[19] = _mm512_xor_si512(a[19], d[4]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[19], 8), _mm512_srli_epi64(a[19], 64 - 8));
		a[20] = _mm512_xor_si512(a[20], d[0]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[20], 18), _mm512_srli_epi64(a[20], 64 - 18));
		e[10] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[11] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[12] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[13] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[14] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[4] = _mm512_xor_si512(a[4], d[4]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[4], 27), _mm512_srli_epi64(a[4], 64 - 27));
		a[5] = _mm512_xor_si512(a[5], d[0]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[5], 36), _mm512_srli_epi64(a[5], 64 - 36));
		a[11] = _mm512_xor_si512(a[11], d[1]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[11], 10), _mm512_srli_epi64(a[11], 64 - 10));
		a[17] = _mm512_xor_si512(a[17], d[2]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[17], 15), _mm512_srli_epi64(a[17], 64 - 15));
		a[23] = _mm512_xor_si512(a[23], d[3]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[23], 56), _mm512_srli_epi64(a[23], 64 - 56));
		e[15] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[16] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[17] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[18] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[19] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[2] = _mm512_xor_si512(a[2], d[2]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[2], 62), _mm512_srli_epi64(a[2], 64 - 62));
		a[8] = _mm512_xor_si512(a[8], d[3]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[8], 55), _mm512_srli_epi64(a[8], 64 - 55));
		a[14] = _mm512_xor_si512(a[14], d[4]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[14], 39), _mm512_srli_epi64(a[14], 64 - 39));
		a[15] = _mm512_xor_si512(a[15], d[0]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[15], 41), _mm512_srli_epi64(a[15], 64 - 41));
		a[21] = _mm512_xor_si512(a[21], d[1]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[21], 2), _mm512_srli_epi64(a[21], 64 - 2));
		e[20] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[21] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[22] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[23] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[24] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));

		/* round n + 1 */
		c[0] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[0], e[5]), _mm512_xor_si512(e[10], e[15])), e[20]);
		c[1] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[1], e[6]), _mm512_xor_si512(e[11], e[16])), e[21]);
		c[2] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[2], e[7]), _mm512_xor_si512(e[12], e[17])), e[22]);
		c[3] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[3], e[8]), _mm512_xor_si512(e[13], e[18])), e[23]);
		c[4] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[4], e[9]), _mm512_xor_si512(e[14], e[19])), e[24]);
		d[0] = _mm512_xor_si512(c[4], _mm512_or_si512(_mm512_slli_epi64(c[1], 1), _mm512_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm512_xor_si512(c[0], _mm512_or_si512(_mm512_slli_epi64(c[2], 1), _mm512_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm512_xor_si512(c[1], _mm512_or_si512(_mm512_slli_epi64(c[3], 1), _mm512_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm512_xor_si512(c[2], _mm512_or_si512(_mm512_slli_epi64(c[4], 1), _mm512_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm512_xor_si512(c[3], _mm512_or_si512(_mm512_slli_epi64(c[0], 1), _mm512_srli_epi64(c[0], 64 - 1)));
		e[0] = _mm512_xor_si512(e[0], d[0]);
		c[0] = e[0];
		e[6] = _mm512_xor_si512(e[6], d[1]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[6], 44), _mm512_srli_epi64(e[6], 64 - 44));
		e[12] = _mm512_xor_si512(e[12], d[2]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[12], 43), _mm512_srli_epi64(e[12], 64 - 43));
		e[18] = _mm512_xor_si512(e[18], d[3]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[18], 21), _mm512_srli_epi64(e[18], 64 - 21));
		e[24] = _mm512_xor_si512(e[24], d[4]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[24], 14), _mm512_srli_epi64(e[24], 64 - 14));
		a[0] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[0] = _mm512_xor_si512(a[0], _mm512_set1_epi64(KECCAK_ROUND_CONSTANTS[i + 1]));
		a[1] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[2] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[3] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[4] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[3] = _mm512_xor_si512(e[3], d[3]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[3], 28), _mm512_srli_epi64(e[3], 64 - 28));
		e[9] = _mm512_xor_si512(e[9], d[4]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[9], 20), _mm512_srli_epi64(e[9], 64 - 20));
		e[10] = _mm512_xor_si512(e[10], d[0]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[10], 3), _mm512_srli_epi64(e[10], 64 - 3));
		e[16] = _mm512_xor_si512(e[16], d[1]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[16], 45), _mm512_srli_epi64(e[16], 64 - 45));
		e[22] = _mm512_xor_si512(e[22], d[2]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[22], 61), _mm512_srli_epi64(e[22], 64 - 61));
		a[5] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[6] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[7] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[8] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[9] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[1] = _mm512_xor_si512(e[1], d[1]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[1], 1), _mm512_srli_epi64(e[1], 64 - 1));
		e[7] = _mm512_xor_si512(e[7], d[2]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[7], 6), _mm512_srli_epi64(e[7], 64 - 6));
		e[13] = _mm512_xor_si512(e[13], d[3]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[13], 25), _mm512_srli_epi64(e[13], 64 - 25));
		e[19] = _mm512_xor_si512(e[19], d[4]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[19], 8), _mm512_srli_epi64(e[19], 64 - 8));
		e[20] = _mm512_xor_si512(e[20], d[0]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[20], 18), _mm512_srli_epi64(e[20], 64 - 18));
		a[10] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[11] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[12] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[13] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[14] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[4] = _mm512_xor_si512(e[4], d[4]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[4], 27), _mm512_srli_epi64(e[4], 64 - 27));
		e[5] = _mm512_xor_si512(e[5], d[0]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[5], 36), _mm512_srli_epi64(e[5], 64 - 36));
		e[11] = _mm512_xor_si512(e[11], d[1]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[11], 10), _mm512_srli_epi64(e[11], 64 - 10));
		e[17] = _mm512_xor_si512(e[17], d[2]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[17], 15), _mm512_srli_epi64(e[17], 64 - 15));
		e[23] = _mm512_xor_si512(e[23], d[3]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[23], 56), _mm512_srli_epi64(e[23], 64 - 56));
		a[15] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[16] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[17] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[18] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[19] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[2] = _mm512_xor_si512(e[2], d[2]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[2], 62), _mm512_srli_epi64(e[2], 64 - 62));
		e[8] = _mm512_xor_si512(e[8], d[3]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[8], 55), _mm512_srli_epi64(e[8], 64 - 55));
		e[14] = _mm512_xor_si512(e[14], d[4]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[14], 39), _mm512_srli_epi64(e[14], 64 - 39));
		e[15] = _mm512_xor_si512(e[15], d[0]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[15], 41), _mm512_srli_epi64(e[15], 64 - 41));
		e[21] = _mm512_xor_si512(e[21], d[1]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[21], 2), _mm512_srli_epi64(e[21], 64 - 2));
		a[20] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[21] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[22] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[23] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[24] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
	}

	for (i = 0; i < HKDS_KECCAK_STATE_SIZE; ++i)
	{
		state[i] = a[i];
	}
}

#	endif
#endif

#if defined(SYSTEM_HAS_AVX2)
#	if defined(HKDS_KECCAK_UNROLLED_PERMUTATION)

void hkds_keccak_permute_p4x1600(__m256i state[HKDS_KECCAK_STATE_SIZE], size_t rounds)
{
	assert(rounds % 2 == 0);

	__m256i a0;
	__m256i a1;
	__m256i a2;
	__m256i a3;
	__m256i a4;
	__m256i a5;
	__m256i a6;
	__m256i a7;
	__m256i a8;
	__m256i a9;
	__m256i a10;
	__m256i a11;
	__m256i a12;
	__m256i a13;
	__m256i a14;
	__m256i a15;
	__m256i a16;
	__m256i a17;
	__m256i a18;
	__m256i a19;
	__m256i a20;
	__m256i a21;
	__m256i a22;
	__m256i a23;
	__m256i a24;
	__m256i c0;
	__m256i c1;
	__m256i c2;
	__m256i c3;
	__m256i c4;
	__m256i d0;
	__m256i d1;
	__m256i d2;
	__m256i d3;
	__m256i d4;
	__m256i e0;
	__m256i e1;
	__m256i e2;
	__m256i e3;
	__m256i e4;
	__m256i e5;
	__m256i e6;
	__m256i e7;
	__m256i e8;
	__m256i e9;
	__m256i e10;
	__m256i e11;
	__m256i e12;
	__m256i e13;
	__m256i e14;
	__m256i e15;
	__m256i e16;
	__m256i e17;
	__m256i e18;
	__m256i e19;
	__m256i e20;
	__m256i e21;
	__m256i e22;
	__m256i e23;
	__m256i e24;


	size_t i;

	a0 = state[0];
	a1 = state[1];
	a2 = state[2];
	a3 = state[3];
	a4 = state[4];
	a5 = state[5];
	a6 = state[6];
	a7 = state[7];
	a8 = state[8];
	a9 = state[9];
	a10 = state[10];
	a11 = state[11];
	a12 = state[12];
	a13 = state[13];
	a14 = state[14];
	a15 = state[15];
	a16 = state[16];
	a17 = state[17];
	a18 = state[18];
	a19 = state[19];
	a20 = state[20];
	a21 = state[21];
	a22 = state[22];
	a23 = state[23];
	a24 = state[24];

	for (i = 0; i < rounds; i += 2)
	{
		/* round n */
		c0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a5), _mm256_xor_si256(a10, a15)), a20);
		c1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a1, a6), _mm256_xor_si256(a11, a16)), a21);
		c2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a2, a7), _mm256_xor_si256(a12, a17)), a22);
		c3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a3, a8), _mm256_xor_si256(a13, a18)), a23);
		c4 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a4, a9), _mm256_xor_si256(a14, a19)), a24);
		d0 = _mm256_xor_si256(c4, _mm256_or_si256(_mm256_slli_epi64(c1, 1), _mm256_srli_epi64(c1, 64 - 1)));
		d1 = _mm256_xor_si256(c0, _mm256_or_si256(_mm256_slli_epi64(c2, 1), _mm256_srli_epi64(c2, 64 - 1)));
		d2 = _mm256_xor_si256(c1, _mm256_or_si256(_mm256_slli_epi64(c3, 1), _mm256_srli_epi64(c3, 64 - 1)));
		d3 = _mm256_xor_si256(c2, _mm256_or_si256(_mm256_slli_epi64(c4, 1), _mm256_srli_epi64(c4, 64 - 1)));
		d4 = _mm256_xor_si256(c3, _mm256_or_si256(_mm256_slli_epi64(c0, 1), _mm256_srli_epi64(c0, 64 - 1)));
		a0 = _mm256_xor_si256(a0, d0);
		c0 = a0;
		a6 = _mm256_xor_si256(a6, d1);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a6, 44), _mm256_srli_epi64(a6, 64 - 44));
		a12 = _mm256_xor_si256(a12, d2);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a12, 43), _mm256_srli_epi64(a12, 64 - 43));
		a18 = _mm256_xor_si256(a18, d3);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a18, 21), _mm256_srli_epi64(a18, 64 - 21));
		a24 = _mm256_xor_si256(a24, d4);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a24, 14), _mm256_srli_epi64(a24, 64 - 14));
		e0 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		e0 = _mm256_xor_si256(e0, _mm256_set1_epi64x(KECCAK_ROUND_CONSTANTS[i]));
		e1 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		e2 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		e3 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		e4 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		a3 = _mm256_xor_si256(a3, d3);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a3, 28), _mm256_srli_epi64(a3, 64 - 28));
		a9 = _mm256_xor_si256(a9, d4);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a9, 20), _mm256_srli_epi64(a9, 64 - 20));
		a10 = _mm256_xor_si256(a10, d0);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a10, 3), _mm256_srli_epi64(a10, 64 - 3));
		a16 = _mm256_xor_si256(a16, d1);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a16, 45), _mm256_srli_epi64(a16, 64 - 45));
		a22 = _mm256_xor_si256(a22, d2);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a22, 61), _mm256_srli_epi64(a22, 64 - 61));
		e5 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		e6 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		e7 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		e8 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		e9 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		a1 = _mm256_xor_si256(a1, d1);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a1, 1), _mm256_srli_epi64(a1, 64 - 1));
		a7 = _mm256_xor_si256(a7, d2);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a7, 6), _mm256_srli_epi64(a7, 64 - 6));
		a13 = _mm256_xor_si256(a13, d3);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a13, 25), _mm256_srli_epi64(a13, 64 - 25));
		a19 = _mm256_xor_si256(a19, d4);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a19, 8), _mm256_srli_epi64(a19, 64 - 8));
		a20 = _mm256_xor_si256(a20, d0);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a20, 18), _mm256_srli_epi64(a20, 64 - 18));
		e10 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		e11 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		e12 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		e13 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		e14 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		a4 = _mm256_xor_si256(a4, d4);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a4, 27), _mm256_srli_epi64(a4, 64 - 27));
		a5 = _mm256_xor_si256(a5, d0);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a5, 36), _mm256_srli_epi64(a5, 64 - 36));
		a11 = _mm256_xor_si256(a11, d1);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a11, 10), _mm256_srli_epi64(a11, 64 - 10));
		a17 = _mm256_xor_si256(a17, d2);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a17, 15), _mm256_srli_epi64(a17, 64 - 15));
		a23 = _mm256_xor_si256(a23, d3);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a23, 56), _mm256_srli_epi64(a23, 64 - 56));
		e15 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		e16 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		e17 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		e18 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		e19 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		a2 = _mm256_xor_si256(a2, d2);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a2, 62), _mm256_srli_epi64(a2, 64 - 62));
		a8 = _mm256_xor_si256(a8, d3);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a8, 55), _mm256_srli_epi64(a8, 64 - 55));
		a14 = _mm256_xor_si256(a14, d4);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a14, 39), _mm256_srli_epi64(a14, 64 - 39));
		a15 = _mm256_xor_si256(a15, d0);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a15, 41), _mm256_srli_epi64(a15, 64 - 41));
		a21 = _mm256_xor_si256(a21, d1);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a21, 2), _mm256_srli_epi64(a21, 64 - 2));
		e20 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		e21 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		e22 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		e23 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		e24 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		/* round n + 1 */
		c0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e0, e5), _mm256_xor_si256(e10, e15)), e20);
		c1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e1, e6), _mm256_xor_si256(e11, e16)), e21);
		c2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e2, e7), _mm256_xor_si256(e12, e17)), e22);
		c3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e3, e8), _mm256_xor_si256(e13, e18)), e23);
		c4 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e4, e9), _mm256_xor_si256(e14, e19)), e24);
		d0 = _mm256_xor_si256(c4, _mm256_or_si256(_mm256_slli_epi64(c1, 1), _mm256_srli_epi64(c1, 64 - 1)));
		d1 = _mm256_xor_si256(c0, _mm256_or_si256(_mm256_slli_epi64(c2, 1), _mm256_srli_epi64(c2, 64 - 1)));
		d2 = _mm256_xor_si256(c1, _mm256_or_si256(_mm256_slli_epi64(c3, 1), _mm256_srli_epi64(c3, 64 - 1)));
		d3 = _mm256_xor_si256(c2, _mm256_or_si256(_mm256_slli_epi64(c4, 1), _mm256_srli_epi64(c4, 64 - 1)));
		d4 = _mm256_xor_si256(c3, _mm256_or_si256(_mm256_slli_epi64(c0, 1), _mm256_srli_epi64(c0, 64 - 1)));
		e0 = _mm256_xor_si256(e0, d0);
		c0 = e0;
		e6 = _mm256_xor_si256(e6, d1);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e6, 44), _mm256_srli_epi64(e6, 64 - 44));
		e12 = _mm256_xor_si256(e12, d2);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e12, 43), _mm256_srli_epi64(e12, 64 - 43));
		e18 = _mm256_xor_si256(e18, d3);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e18, 21), _mm256_srli_epi64(e18, 64 - 21));
		e24 = _mm256_xor_si256(e24, d4);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e24, 14), _mm256_srli_epi64(e24, 64 - 14));
		a0 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		a0 = _mm256_xor_si256(a0, _mm256_set1_epi64x(KECCAK_ROUND_CONSTANTS[i + 1]));
		a1 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		a2 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		a3 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		a4 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		e3 = _mm256_xor_si256(e3, d3);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e3, 28), _mm256_srli_epi64(e3, 64 - 28));
		e9 = _mm256_xor_si256(e9, d4);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e9, 20), _mm256_srli_epi64(e9, 64 - 20));
		e10 = _mm256_xor_si256(e10, d0);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e10, 3), _mm256_srli_epi64(e10, 64 - 3));
		e16 = _mm256_xor_si256(e16, d1);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e16, 45), _mm256_srli_epi64(e16, 64 - 45));
		e22 = _mm256_xor_si256(e22, d2);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e22, 61), _mm256_srli_epi64(e22, 64 - 61));
		a5 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		a6 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		a7 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		a8 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		a9 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		e1 = _mm256_xor_si256(e1, d1);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e1, 1), _mm256_srli_epi64(e1, 64 - 1));
		e7 = _mm256_xor_si256(e7, d2);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e7, 6), _mm256_srli_epi64(e7, 64 - 6));
		e13 = _mm256_xor_si256(e13, d3);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e13, 25), _mm256_srli_epi64(e13, 64 - 25));
		e19 = _mm256_xor_si256(e19, d4);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e19, 8), _mm256_srli_epi64(e19, 64 - 8));
		e20 = _mm256_xor_si256(e20, d0);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e20, 18), _mm256_srli_epi64(e20, 64 - 18));
		a10 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		a11 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		a12 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		a13 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		a14 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		e4 = _mm256_xor_si256(e4, d4);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e4, 27), _mm256_srli_epi64(e4, 64 - 27));
		e5 = _mm256_xor_si256(e5, d0);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e5, 36), _mm256_srli_epi64(e5, 64 - 36));
		e11 = _mm256_xor_si256(e11, d1);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e11, 10), _mm256_srli_epi64(e11, 64 - 10));
		e17 = _mm256_xor_si256(e17, d2);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e17, 15), _mm256_srli_epi64(e17, 64 - 15));
		e23 = _mm256_xor_si256(e23, d3);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e23, 56), _mm256_srli_epi64(e23, 64 - 56));
		a15 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		a16 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		a17 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		a18 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		a19 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
		e2 = _mm256_xor_si256(e2, d2);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e2, 62), _mm256_srli_epi64(e2, 64 - 62));
		e8 = _mm256_xor_si256(e8, d3);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e8, 55), _mm256_srli_epi64(e8, 64 - 55));
		e14 = _mm256_xor_si256(e14, d4);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e14, 39), _mm256_srli_epi64(e14, 64 - 39));
		e15 = _mm256_xor_si256(e15, d0);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e15, 41), _mm256_srli_epi64(e15, 64 - 41));
		e21 = _mm256_xor_si256(e21, d1);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e21, 2), _mm256_srli_epi64(e21, 64 - 2));
		a20 = _mm256_xor_si256(c0, _mm256_and_si256(_mm256_xor_si256(c1, _mm256_set1_epi64x(-1)), c2));
		a21 = _mm256_xor_si256(c1, _mm256_and_si256(_mm256_xor_si256(c2, _mm256_set1_epi64x(-1)), c3));
		a22 = _mm256_xor_si256(c2, _mm256_and_si256(_mm256_xor_si256(c3, _mm256_set1_epi64x(-1)), c4));
		a23 = _mm256_xor_si256(c3, _mm256_and_si256(_mm256_xor_si256(c4, _mm256_set1_epi64x(-1)), c0));
		a24 = _mm256_xor_si256(c4, _mm256_and_si256(_mm256_xor_si256(c0, _mm256_set1_epi64x(-1)), c1));
	}

	state[0] = a0;
	state[1] = a1;
	state[2] = a2;
	state[3] = a3;
	state[4] = a4;
	state[5] = a5;
	state[6] = a6;
	state[7] = a7;
	state[8] = a8;
	state[9] = a9;
	state[10] = a10;
	state[11] = a11;
	state[12] = a12;
	state[13] = a13;
	state[14] = a14;
	state[15] = a15;
	state[16] = a16;
	state[17] = a17;
	state[18] = a18;
	state[19] = a19;
	state[20] = a20;
	state[21] = a21;
	state[22] = a22;
	state[23] = a23;
	state[24] = a24;
}

#	else

void hkds_keccak_permute_p4x1600(__m256i state[HKDS_KECCAK_STATE_SIZE], size_t rounds)
{
	assert(rounds % 2 == 0);

	__m256i a[25] = { 0 };
	__m256i c[5] = { 0 };
	__m256i d[5] = { 0 };
	__m256i e[25] = { 0 };
	size_t i;

	for (i = 0; i < HKDS_KECCAK_STATE_SIZE; ++i)
	{
		a[i] = state[i];
	}

	for (i = 0; i < rounds; i += 2)
	{
		/* round n */
		c[0] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[0], a[5]), _mm256_xor_si256(a[10], a[15])), a[20]);
		c[1] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[1], a[6]), _mm256_xor_si256(a[11], a[16])), a[21]);
		c[2] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[2], a[7]), _mm256_xor_si256(a[12], a[17])), a[22]);
		c[3] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[3], a[8]), _mm256_xor_si256(a[13], a[18])), a[23]);
		c[4] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[4], a[9]), _mm256_xor_si256(a[14], a[19])), a[24]);
		d[0] = _mm256_xor_si256(c[4], _mm256_or_si256(_mm256_slli_epi64(c[1], 1), _mm256_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm256_xor_si256(c[0], _mm256_or_si256(_mm256_slli_epi64(c[2], 1), _mm256_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm256_xor_si256(c[1], _mm256_or_si256(_mm256_slli_epi64(c[3], 1), _mm256_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm256_xor_si256(c[2], _mm256_or_si256(_mm256_slli_epi64(c[4], 1), _mm256_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm256_xor_si256(c[3], _mm256_or_si256(_mm256_slli_epi64(c[0], 1), _mm256_srli_epi64(c[0], 64 - 1)));
		a[0] = _mm256_xor_si256(a[0], d[0]);
		c[0] = a[0];
		a[6] = _mm256_xor_si256(a[6], d[1]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[6], 44), _mm256_srli_epi64(a[6], 64 - 44));
		a[12] = _mm256_xor_si256(a[12], d[2]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[12], 43), _mm256_srli_epi64(a[12], 64 - 43));
		a[18] = _mm256_xor_si256(a[18], d[3]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[18], 21), _mm256_srli_epi64(a[18], 64 - 21));
		a[24] = _mm256_xor_si256(a[24], d[4]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[24], 14), _mm256_srli_epi64(a[24], 64 - 14));
		e[0] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[0] = _mm256_xor_si256(e[0], _mm256_set1_epi64x(KECCAK_ROUND_CONSTANTS[i]));
		e[1] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[2] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[3] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[4] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[3] = _mm256_xor_si256(a[3], d[3]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[3], 28), _mm256_srli_epi64(a[3], 64 - 28));
		a[9] = _mm256_xor_si256(a[9], d[4]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[9], 20), _mm256_srli_epi64(a[9], 64 - 20));
		a[10] = _mm256_xor_si256(a[10], d[0]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[10], 3), _mm256_srli_epi64(a[10], 64 - 3));
		a[16] = _mm256_xor_si256(a[16], d[1]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[16], 45), _mm256_srli_epi64(a[16], 64 - 45));
		a[22] = _mm256_xor_si256(a[22], d[2]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[22], 61), _mm256_srli_epi64(a[22], 64 - 61));
		e[5] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[6] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[7] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[8] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[9] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[1] = _mm256_xor_si256(a[1], d[1]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[1], 1), _mm256_srli_epi64(a[1], 64 - 1));
		a[7] = _mm256_xor_si256(a[7], d[2]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[7], 6), _mm256_srli_epi64(a[7], 64 - 6));
		a[13] = _mm256_xor_si256(a[13], d[3]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[13], 25), _mm256_srli_epi64(a[13], 64 - 25));
		a[19] = _mm256_xor_si256(a[19], d[4]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[19], 8), _mm256_srli_epi64(a[19], 64 - 8));
		a[20] = _mm256_xor_si256(a[20], d[0]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[20], 18), _mm256_srli_epi64(a[20], 64 - 18));
		e[10] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[11] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[12] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[13] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[14] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[4] = _mm256_xor_si256(a[4], d[4]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[4], 27), _mm256_srli_epi64(a[4], 64 - 27));
		a[5] = _mm256_xor_si256(a[5], d[0]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[5], 36), _mm256_srli_epi64(a[5], 64 - 36));
		a[11] = _mm256_xor_si256(a[11], d[1]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[11], 10), _mm256_srli_epi64(a[11], 64 - 10));
		a[17] = _mm256_xor_si256(a[17], d[2]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[17], 15), _mm256_srli_epi64(a[17], 64 - 15));
		a[23] = _mm256_xor_si256(a[23], d[3]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[23], 56), _mm256_srli_epi64(a[23], 64 - 56));
		e[15] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[16] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[17] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[18] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[19] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[2] = _mm256_xor_si256(a[2], d[2]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[2], 62), _mm256_srli_epi64(a[2], 64 - 62));
		a[8] = _mm256_xor_si256(a[8], d[3]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[8], 55), _mm256_srli_epi64(a[8], 64 - 55));
		a[14] = _mm256_xor_si256(a[14], d[4]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[14], 39), _mm256_srli_epi64(a[14], 64 - 39));
		a[15] = _mm256_xor_si256(a[15], d[0]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[15], 41), _mm256_srli_epi64(a[15], 64 - 41));
		a[21] = _mm256_xor_si256(a[21], d[1]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[21], 2), _mm256_srli_epi64(a[21], 64 - 2));
		e[20] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[21] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[22] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[23] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[24] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));

		/* round n + 1 */
		c[0] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[0], e[5]), _mm256_xor_si256(e[10], e[15])), e[20]);
		c[1] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[1], e[6]), _mm256_xor_si256(e[11], e[16])), e[21]);
		c[2] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[2], e[7]), _mm256_xor_si256(e[12], e[17])), e[22]);
		c[3] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[3], e[8]), _mm256_xor_si256(e[13], e[18])), e[23]);
		c[4] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[4], e[9]), _mm256_xor_si256(e[14], e[19])), e[24]);
		d[0] = _mm256_xor_si256(c[4], _mm256_or_si256(_mm256_slli_epi64(c[1], 1), _mm256_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm256_xor_si256(c[0], _mm256_or_si256(_mm256_slli_epi64(c[2], 1), _mm256_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm256_xor_si256(c[1], _mm256_or_si256(_mm256_slli_epi64(c[3], 1), _mm256_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm256_xor_si256(c[2], _mm256_or_si256(_mm256_slli_epi64(c[4], 1), _mm256_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm256_xor_si256(c[3], _mm256_or_si256(_mm256_slli_epi64(c[0], 1), _mm256_srli_epi64(c[0], 64 - 1)));
		e[0] = _mm256_xor_si256(e[0], d[0]);
		c[0] = e[0];
		e[6] = _mm256_xor_si256(e[6], d[1]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[6], 44), _mm256_srli_epi64(e[6], 64 - 44));
		e[12] = _mm256_xor_si256(e[12], d[2]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[12], 43), _mm256_srli_epi64(e[12], 64 - 43));
		e[18] = _mm256_xor_si256(e[18], d[3]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[18], 21), _mm256_srli_epi64(e[18], 64 - 21));
		e[24] = _mm256_xor_si256(e[24], d[4]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[24], 14), _mm256_srli_epi64(e[24], 64 - 14));
		a[0] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(KECCAK_ROUND_CONSTANTS[i + 1]));
		a[1] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[2] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[3] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[4] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[3] = _mm256_xor_si256(e[3], d[3]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[3], 28), _mm256_srli_epi64(e[3], 64 - 28));
		e[9] = _mm256_xor_si256(e[9], d[4]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[9], 20), _mm256_srli_epi64(e[9], 64 - 20));
		e[10] = _mm256_xor_si256(e[10], d[0]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[10], 3), _mm256_srli_epi64(e[10], 64 - 3));
		e[16] = _mm256_xor_si256(e[16], d[1]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[16], 45), _mm256_srli_epi64(e[16], 64 - 45));
		e[22] = _mm256_xor_si256(e[22], d[2]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[22], 61), _mm256_srli_epi64(e[22], 64 - 61));
		a[5] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[6] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[7] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[8] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[9] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[1] = _mm256_xor_si256(e[1], d[1]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[1], 1), _mm256_srli_epi64(e[1], 64 - 1));
		e[7] = _mm256_xor_si256(e[7], d[2]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[7], 6), _mm256_srli_epi64(e[7], 64 - 6));
		e[13] = _mm256_xor_si256(e[13], d[3]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[13], 25), _mm256_srli_epi64(e[13], 64 - 25));
		e[19] = _mm256_xor_si256(e[19], d[4]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[19], 8), _mm256_srli_epi64(e[19], 64 - 8));
		e[20] = _mm256_xor_si256(e[20], d[0]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[20], 18), _mm256_srli_epi64(e[20], 64 - 18));
		a[10] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[11] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[12] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[13] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[14] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[4] = _mm256_xor_si256(e[4], d[4]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[4], 27), _mm256_srli_epi64(e[4], 64 - 27));
		e[5] = _mm256_xor_si256(e[5], d[0]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[5], 36), _mm256_srli_epi64(e[5], 64 - 36));
		e[11] = _mm256_xor_si256(e[11], d[1]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[11], 10), _mm256_srli_epi64(e[11], 64 - 10));
		e[17] = _mm256_xor_si256(e[17], d[2]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[17], 15), _mm256_srli_epi64(e[17], 64 - 15));
		e[23] = _mm256_xor_si256(e[23], d[3]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[23], 56), _mm256_srli_epi64(e[23], 64 - 56));
		a[15] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[16] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[17] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[18] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[19] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[2] = _mm256_xor_si256(e[2], d[2]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[2], 62), _mm256_srli_epi64(e[2], 64 - 62));
		e[8] = _mm256_xor_si256(e[8], d[3]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[8], 55), _mm256_srli_epi64(e[8], 64 - 55));
		e[14] = _mm256_xor_si256(e[14], d[4]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[14], 39), _mm256_srli_epi64(e[14], 64 - 39));
		e[15] = _mm256_xor_si256(e[15], d[0]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[15], 41), _mm256_srli_epi64(e[15], 64 - 41));
		e[21] = _mm256_xor_si256(e[21], d[1]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[21], 2), _mm256_srli_epi64(e[21], 64 - 2));
		a[20] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[21] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[22] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[23] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[24] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
	}

	for (i = 0; i < HKDS_KECCAK_STATE_SIZE; ++i)
	{
		state[i] = a[i];
	}
}

#	endif
#endif

/* Keccak */

void hkds_keccak_absorb(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* message, size_t msglen, uint8_t domain, size_t rounds)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (ctx != NULL && message != NULL)
	{
		uint8_t msg[HKDS_KECCAK_STATE_BYTE_SIZE];

		while (msglen >= (size_t)rate)
		{
#if defined(SYSTEM_IS_LITTLE_ENDIAN)
			utils_memory_xor((uint8_t*)ctx->state, message, rate);
#else
			for (size_t i = 0; i < rate / sizeof(uint64_t); ++i)
			{
				ctx->state[i] ^= utils_integer_le8to64((message + (sizeof(uint64_t) * i)));
			}
#endif
			hkds_keccak_permute(ctx, rounds);
			msglen -= rate;
			message += rate;
		}

		utils_memory_copy(msg, message, msglen);
		msg[msglen] = domain;
		utils_memory_clear((msg + msglen + 1), rate - msglen + 1);
		msg[rate - 1] |= 128U;

#if defined(SYSTEM_IS_LITTLE_ENDIAN)
		utils_memory_xor((uint8_t*)ctx->state, msg, rate);
#else
		for (size_t i = 0; i < rate / 8; ++i)
		{
			ctx->state[i] ^= utils_integer_le8to64((msg + (8 * i)));
		}
#endif
	}
}

void hkds_keccak_absorb_custom(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds)
{
	assert(ctx != NULL);

	uint8_t pad[HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t i;
	size_t oft;

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((pad + oft), namelen * 8);

	if (name != NULL)
	{
		for (i = 0; i < namelen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				hkds_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = name[i];
			++oft;
		}
	}

	oft += keccak_left_encode((pad + oft), custlen * 8);

	if (custom != NULL)
	{
		for (i = 0; i < custlen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				hkds_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = custom[i];
			++oft;
		}
	}

	utils_memory_clear((pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	hkds_keccak_permute(ctx, rounds);
}

void hkds_keccak_absorb_key_custom(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds)
{
	assert(ctx != NULL);

	uint8_t pad[HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t oft;
	size_t i;

	utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
	utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((pad + oft), namelen * 8);

	if (name != NULL)
	{
		for (i = 0; i < namelen; ++i)
		{
			pad[oft + i] = name[i];
		}
	}

	oft += namelen;
	oft += keccak_left_encode((pad + oft), custlen * 8);

	if (custom != NULL)
	{
		for (i = 0; i < custlen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				hkds_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = custom[i];
			++oft;
		}
	}

	utils_memory_clear((pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	hkds_keccak_permute(ctx, rounds);


	/* stage 2: key */

	utils_memory_clear(pad, rate);

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((pad + oft), keylen * 8);

	if (key != NULL)
	{
		for (i = 0; i < keylen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				hkds_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = key[i];
			++oft;
		}
	}

	utils_memory_clear((pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	hkds_keccak_permute(ctx, rounds);
}

void hkds_keccak_dispose(hkds_keccak_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0;
	}
}

void hkds_keccak_finalize(hkds_keccak_state* ctx, hkds_keccak_rate rate, uint8_t* output, size_t outlen, uint8_t domain, size_t rounds)
{
	assert(ctx != NULL);
	assert(output != NULL);

	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t bitlen;

	utils_memory_copy(pad, ctx->buffer, ctx->position);
	bitlen = keccak_right_encode(buf, outlen * 8);

	if (ctx->position + bitlen >= (size_t)rate)
	{
		keccak_fast_absorb(ctx->state, pad, ctx->position);
		hkds_keccak_permute(ctx, rounds);
		ctx->position = 0;
	}

	utils_memory_copy((pad + ctx->position), buf, bitlen);

	pad[ctx->position + bitlen] = domain;
	pad[rate - 1] |= 128U;
	keccak_fast_absorb(ctx->state, pad, rate);

	while (outlen >= (size_t)rate)
	{
		hkds_keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		utils_memory_copy(output, pad, rate);
		output += rate;
		outlen -= rate;
	}

	if (outlen > 0)
	{
		hkds_keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		utils_memory_copy(output, pad, outlen);
	}

	utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;
}

void hkds_keccak_incremental_absorb(hkds_keccak_state* ctx, uint32_t rate, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	uint8_t t[8] = { 0 };
	size_t i;

	if ((ctx->position & 7) > 0)
	{
		i = ctx->position & 7;

		while (i < 8 && msglen > 0)
		{
			t[i] = *message;
			message++;
			i++;
			msglen--;
			ctx->position++;
		}

		ctx->state[(ctx->position - i) / 8] ^= utils_integer_le8to64(t);
	}

	if (ctx->position && msglen >= rate - ctx->position)
	{
		for (i = 0; i < (rate - ctx->position) / 8; ++i)
		{
			ctx->state[(ctx->position / 8) + i] ^= utils_integer_le8to64(message + (8 * i));
		}

		message += rate - ctx->position;
		msglen -= rate - ctx->position;
		ctx->position = 0;
		hkds_keccak_permute_p1600c(ctx->state, HKDS_KECCAK_PERMUTATION_ROUNDS);
	}

	while (msglen >= rate)
	{
		for (i = 0; i < rate / 8; i++)
		{
			ctx->state[i] ^= utils_integer_le8to64(message + (8 * i));
		}

		message += rate;
		msglen -= rate;
		hkds_keccak_permute_p1600c(ctx->state, HKDS_KECCAK_PERMUTATION_ROUNDS);
	}

	for (i = 0; i < msglen / 8; ++i)
	{
		ctx->state[(ctx->position / 8) + i] ^= utils_integer_le8to64(message + (8 * i));
	}

	message += 8 * i;
	msglen -= 8 * i;
	ctx->position += 8 * i;

	if (msglen > 0)
	{
		for (i = 0; i < 8; ++i)
		{
			t[i] = 0;
		}

		for (i = 0; i < msglen; ++i)
		{
			t[i] = message[i];
		}

		ctx->state[ctx->position / 8] ^= utils_integer_le8to64(t);
		ctx->position += msglen;
	}
}

void hkds_keccak_incremental_finalize(hkds_keccak_state* ctx, uint32_t rate, uint8_t domain)
{
	assert(ctx != NULL);
	
	size_t i;
	size_t j;

	i = ctx->position >> 3;
	j = ctx->position & 7;
	ctx->state[i] ^= ((uint64_t)domain << (8 * j));
	ctx->state[(rate / 8) - 1] ^= 1ULL << 63;
	ctx->position = 0;
}

void hkds_keccak_incremental_squeeze(hkds_keccak_state* ctx, size_t rate, uint8_t* output, size_t outlen)
{
	assert(ctx != NULL);
	assert(output != NULL);

	size_t i;
	uint8_t t[8];

	if ((ctx->position & 7) > 0)
	{
		utils_integer_le64to8(t, ctx->state[ctx->position / 8]);
		i = ctx->position & 7;

		while (i < 8 && outlen > 0)
		{
			*output = t[i];
			output++;
			i++;
			outlen--;
			ctx->position++;
		}
	}

	if (ctx->position && outlen >= rate - ctx->position)
	{
		for (i = 0; i < (rate - ctx->position) / 8; ++i)
		{
			utils_integer_le64to8(output + (8 * i), ctx->state[(ctx->position / 8) + i]);
		}

		output += rate - ctx->position;
		outlen -= rate - ctx->position;
		ctx->position = 0;
	}

	while (outlen >= rate)
	{
		hkds_keccak_permute_p1600c(ctx->state, HKDS_KECCAK_PERMUTATION_ROUNDS);

		for (i = 0; i < rate / 8; ++i)
		{
			utils_integer_le64to8(output + (8 * i), ctx->state[i]);
		}

		output += rate;
		outlen -= rate;
	}

	if (outlen > 0)
	{
		if (ctx->position == 0)
		{
			hkds_keccak_permute_p1600c(ctx->state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		}

		for (i = 0; i < outlen / 8; ++i)
		{
			utils_integer_le64to8(output + (8 * i), ctx->state[(ctx->position / 8) + i]);
		}

		output += 8 * i;
		outlen -= 8 * i;
		ctx->position += 8 * i;

		utils_integer_le64to8(t, ctx->state[ctx->position / 8]);

		for (i = 0; i < outlen; ++i)
		{
			output[i] = t[i];
		}

		ctx->position += outlen;
	}
}

void hkds_keccak_permute(hkds_keccak_state* ctx, size_t rounds)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
#if defined(HKDS_KECCAK_UNROLLED_PERMUTATION)
		hkds_keccak_permute_p1600u(ctx->state)
#else
		hkds_keccak_permute_p1600c(ctx->state, rounds);
#endif
	}
}

void hkds_keccak_permute_p1600c(uint64_t* state, size_t rounds)
{
	assert(state != NULL);
	assert(rounds % 2 == 0);

	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t BCa;
	uint64_t BCe;
	uint64_t BCi;
	uint64_t BCo;
	uint64_t BCu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	/* copyFromState(A, state) */
	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	for (size_t i = 0; i < rounds; i += 2)
	{
		/* prepareTheta */
		BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ utils_integer_rotl64(BCe, 1);
		De = BCa ^ utils_integer_rotl64(BCi, 1);
		Di = BCe ^ utils_integer_rotl64(BCo, 1);
		Do = BCi ^ utils_integer_rotl64(BCu, 1);
		Du = BCo ^ utils_integer_rotl64(BCa, 1);

		Aba ^= Da;
		BCa = Aba;
		Age ^= De;
		BCe = utils_integer_rotl64(Age, 44);
		Aki ^= Di;
		BCi = utils_integer_rotl64(Aki, 43);
		Amo ^= Do;
		BCo = utils_integer_rotl64(Amo, 21);
		Asu ^= Du;
		BCu = utils_integer_rotl64(Asu, 14);
		Eba = BCa ^ ((~BCe) & BCi);
		Eba ^= KECCAK_ROUND_CONSTANTS[i];
		Ebe = BCe ^ ((~BCi) & BCo);
		Ebi = BCi ^ ((~BCo) & BCu);
		Ebo = BCo ^ ((~BCu) & BCa);
		Ebu = BCu ^ ((~BCa) & BCe);

		Abo ^= Do;
		BCa = utils_integer_rotl64(Abo, 28);
		Agu ^= Du;
		BCe = utils_integer_rotl64(Agu, 20);
		Aka ^= Da;
		BCi = utils_integer_rotl64(Aka, 3);
		Ame ^= De;
		BCo = utils_integer_rotl64(Ame, 45);
		Asi ^= Di;
		BCu = utils_integer_rotl64(Asi, 61);
		Ega = BCa ^ ((~BCe) & BCi);
		Ege = BCe ^ ((~BCi) & BCo);
		Egi = BCi ^ ((~BCo) & BCu);
		Ego = BCo ^ ((~BCu) & BCa);
		Egu = BCu ^ ((~BCa) & BCe);

		Abe ^= De;
		BCa = utils_integer_rotl64(Abe, 1);
		Agi ^= Di;
		BCe = utils_integer_rotl64(Agi, 6);
		Ako ^= Do;
		BCi = utils_integer_rotl64(Ako, 25);
		Amu ^= Du;
		BCo = utils_integer_rotl64(Amu, 8);
		Asa ^= Da;
		BCu = utils_integer_rotl64(Asa, 18);
		Eka = BCa ^ ((~BCe) & BCi);
		Eke = BCe ^ ((~BCi) & BCo);
		Eki = BCi ^ ((~BCo) & BCu);
		Eko = BCo ^ ((~BCu) & BCa);
		Eku = BCu ^ ((~BCa) & BCe);

		Abu ^= Du;
		BCa = utils_integer_rotl64(Abu, 27);
		Aga ^= Da;
		BCe = utils_integer_rotl64(Aga, 36);
		Ake ^= De;
		BCi = utils_integer_rotl64(Ake, 10);
		Ami ^= Di;
		BCo = utils_integer_rotl64(Ami, 15);
		Aso ^= Do;
		BCu = utils_integer_rotl64(Aso, 56);
		Ema = BCa ^ ((~BCe) & BCi);
		Eme = BCe ^ ((~BCi) & BCo);
		Emi = BCi ^ ((~BCo) & BCu);
		Emo = BCo ^ ((~BCu) & BCa);
		Emu = BCu ^ ((~BCa) & BCe);

		Abi ^= Di;
		BCa = utils_integer_rotl64(Abi, 62);
		Ago ^= Do;
		BCe = utils_integer_rotl64(Ago, 55);
		Aku ^= Du;
		BCi = utils_integer_rotl64(Aku, 39);
		Ama ^= Da;
		BCo = utils_integer_rotl64(Ama, 41);
		Ase ^= De;
		BCu = utils_integer_rotl64(Ase, 2);
		Esa = BCa ^ ((~BCe) & BCi);
		Ese = BCe ^ ((~BCi) & BCo);
		Esi = BCi ^ ((~BCo) & BCu);
		Eso = BCo ^ ((~BCu) & BCa);
		Esu = BCu ^ ((~BCa) & BCe);

		/* prepareTheta */
		BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ utils_integer_rotl64(BCe, 1);
		De = BCa ^ utils_integer_rotl64(BCi, 1);
		Di = BCe ^ utils_integer_rotl64(BCo, 1);
		Do = BCi ^ utils_integer_rotl64(BCu, 1);
		Du = BCo ^ utils_integer_rotl64(BCa, 1);

		Eba ^= Da;
		BCa = Eba;
		Ege ^= De;
		BCe = utils_integer_rotl64(Ege, 44);
		Eki ^= Di;
		BCi = utils_integer_rotl64(Eki, 43);
		Emo ^= Do;
		BCo = utils_integer_rotl64(Emo, 21);
		Esu ^= Du;
		BCu = utils_integer_rotl64(Esu, 14);
		Aba = BCa ^ ((~BCe) & BCi);
		Aba ^= KECCAK_ROUND_CONSTANTS[i + 1];
		Abe = BCe ^ ((~BCi) & BCo);
		Abi = BCi ^ ((~BCo) & BCu);
		Abo = BCo ^ ((~BCu) & BCa);
		Abu = BCu ^ ((~BCa) & BCe);

		Ebo ^= Do;
		BCa = utils_integer_rotl64(Ebo, 28);
		Egu ^= Du;
		BCe = utils_integer_rotl64(Egu, 20);
		Eka ^= Da;
		BCi = utils_integer_rotl64(Eka, 3);
		Eme ^= De;
		BCo = utils_integer_rotl64(Eme, 45);
		Esi ^= Di;
		BCu = utils_integer_rotl64(Esi, 61);
		Aga = BCa ^ ((~BCe) & BCi);
		Age = BCe ^ ((~BCi) & BCo);
		Agi = BCi ^ ((~BCo) & BCu);
		Ago = BCo ^ ((~BCu) & BCa);
		Agu = BCu ^ ((~BCa) & BCe);

		Ebe ^= De;
		BCa = utils_integer_rotl64(Ebe, 1);
		Egi ^= Di;
		BCe = utils_integer_rotl64(Egi, 6);
		Eko ^= Do;
		BCi = utils_integer_rotl64(Eko, 25);
		Emu ^= Du;
		BCo = utils_integer_rotl64(Emu, 8);
		Esa ^= Da;
		BCu = utils_integer_rotl64(Esa, 18);
		Aka = BCa ^ ((~BCe) & BCi);
		Ake = BCe ^ ((~BCi) & BCo);
		Aki = BCi ^ ((~BCo) & BCu);
		Ako = BCo ^ ((~BCu) & BCa);
		Aku = BCu ^ ((~BCa) & BCe);

		Ebu ^= Du;
		BCa = utils_integer_rotl64(Ebu, 27);
		Ega ^= Da;
		BCe = utils_integer_rotl64(Ega, 36);
		Eke ^= De;
		BCi = utils_integer_rotl64(Eke, 10);
		Emi ^= Di;
		BCo = utils_integer_rotl64(Emi, 15);
		Eso ^= Do;
		BCu = utils_integer_rotl64(Eso, 56);
		Ama = BCa ^ ((~BCe) & BCi);
		Ame = BCe ^ ((~BCi) & BCo);
		Ami = BCi ^ ((~BCo) & BCu);
		Amo = BCo ^ ((~BCu) & BCa);
		Amu = BCu ^ ((~BCa) & BCe);

		Ebi ^= Di;
		BCa = utils_integer_rotl64(Ebi, 62);
		Ego ^= Do;
		BCe = utils_integer_rotl64(Ego, 55);
		Eku ^= Du;
		BCi = utils_integer_rotl64(Eku, 39);
		Ema ^= Da;
		BCo = utils_integer_rotl64(Ema, 41);
		Ese ^= De;
		BCu = utils_integer_rotl64(Ese, 2);
		Asa = BCa ^ ((~BCe) & BCi);
		Ase = BCe ^ ((~BCi) & BCo);
		Asi = BCi ^ ((~BCo) & BCu);
		Aso = BCo ^ ((~BCu) & BCa);
		Asu = BCu ^ ((~BCa) & BCe);
	}

	/* copy to state */
	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

void hkds_keccak_permute_p1600u(uint64_t* state)
{
	assert(state != NULL);

	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t Ca;
	uint64_t Ce;
	uint64_t Ci;
	uint64_t Co;
	uint64_t Cu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	/* round 1 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000000000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 2 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000008082ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 3 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x800000000000808AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 4 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008000ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 5 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 6 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000080000001ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 7 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 8 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008009ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 9 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000008AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 10 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000000088ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 11 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080008009ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 12 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x000000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 13 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000008000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 14 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000000000008BULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 15 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008089ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 16 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008003ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 17 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008002ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 18 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000000080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 19 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000800AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 20 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 21 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 22 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 23 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = utils_integer_rotl64(Age, 44);
	Aki ^= Di;
	Ci = utils_integer_rotl64(Aki, 43);
	Amo ^= Do;
	Co = utils_integer_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = utils_integer_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = utils_integer_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = utils_integer_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = utils_integer_rotl64(Aka, 3);
	Ame ^= De;
	Co = utils_integer_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = utils_integer_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = utils_integer_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = utils_integer_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = utils_integer_rotl64(Ako, 25);
	Amu ^= Du;
	Co = utils_integer_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = utils_integer_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = utils_integer_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = utils_integer_rotl64(Aga, 36);
	Ake ^= De;
	Ci = utils_integer_rotl64(Ake, 10);
	Ami ^= Di;
	Co = utils_integer_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = utils_integer_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = utils_integer_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = utils_integer_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = utils_integer_rotl64(Aku, 39);
	Ama ^= Da;
	Co = utils_integer_rotl64(Ama, 41);
	Ase ^= De;
	Cu = utils_integer_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 24 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ utils_integer_rotl64(Ce, 1);
	De = Ca ^ utils_integer_rotl64(Ci, 1);
	Di = Ce ^ utils_integer_rotl64(Co, 1);
	Do = Ci ^ utils_integer_rotl64(Cu, 1);
	Du = Co ^ utils_integer_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = utils_integer_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = utils_integer_rotl64(Eki, 43);
	Emo ^= Do;
	Co = utils_integer_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = utils_integer_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008008ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = utils_integer_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = utils_integer_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = utils_integer_rotl64(Eka, 3);
	Eme ^= De;
	Co = utils_integer_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = utils_integer_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = utils_integer_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = utils_integer_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = utils_integer_rotl64(Eko, 25);
	Emu ^= Du;
	Co = utils_integer_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = utils_integer_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = utils_integer_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = utils_integer_rotl64(Ega, 36);
	Eke ^= De;
	Ci = utils_integer_rotl64(Eke, 10);
	Emi ^= Di;
	Co = utils_integer_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = utils_integer_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = utils_integer_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = utils_integer_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = utils_integer_rotl64(Eku, 39);
	Ema ^= Da;
	Co = utils_integer_rotl64(Ema, 41);
	Ese ^= De;
	Cu = utils_integer_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);

	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

void hkds_keccak_squeezeblocks(hkds_keccak_state* ctx, uint8_t* output, size_t nblocks, hkds_keccak_rate rate, size_t rounds)
{
	assert(ctx != NULL);
	assert(output != NULL);

	if (ctx != NULL && output != NULL)
	{
		while (nblocks > 0)
		{
			hkds_keccak_permute(ctx, rounds);

#if defined(SYSTEM_IS_LITTLE_ENDIAN)
			utils_memory_copy(output, (uint8_t*)ctx->state, rate);
#else
			for (size_t i = 0; i < (rate >> 3); ++i)
			{
				utils_integer_le64to8((output + sizeof(uint64_t) * i), ctx->state[i]);
			}
#endif
			output += rate;
			nblocks--;
		}
	}
}

void hkds_keccak_initialize_state(hkds_keccak_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0;
	}
}

void hkds_keccak_update(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* message, size_t msglen, size_t rounds)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (ctx != NULL && message != NULL && msglen != 0)
	{
		if (ctx->position != 0 && (ctx->position + msglen >= (size_t)rate))
		{
			const size_t RMDLEN = rate - ctx->position;

			if (RMDLEN != 0)
			{
				utils_memory_copy((ctx->buffer + ctx->position), message, RMDLEN);
			}

			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			hkds_keccak_permute(ctx, rounds);
			ctx->position = 0;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= (size_t)rate)
		{
			keccak_fast_absorb(ctx->state, message, rate);
			hkds_keccak_permute(ctx, rounds);
			message += rate;
			msglen -= rate;
		}

		/* store unaligned bytes */
		if (msglen != 0)
		{
			utils_memory_copy((ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}

/* SHAKE */

void hkds_shake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / HKDS_KECCAK_128_RATE;
	hkds_keccak_state ctx;
	uint8_t hash[HKDS_KECCAK_128_RATE] = { 0 };

	hkds_shake_initialize(&ctx, hkds_keccak_rate_128, key, keylen);
	hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_128, output, nblocks);
	output += (nblocks * HKDS_KECCAK_128_RATE);
	outlen -= (nblocks * HKDS_KECCAK_128_RATE);

	if (outlen != 0)
	{
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_128, hash, 1);
		utils_memory_copy(output, hash, outlen);
	}

	hkds_keccak_dispose(&ctx);
}

void hkds_shake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / HKDS_KECCAK_256_RATE;
	hkds_keccak_state ctx;
	uint8_t hash[HKDS_KECCAK_256_RATE] = { 0 };

	hkds_shake_initialize(&ctx, hkds_keccak_rate_256, key, keylen);
	hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_256, output, nblocks);
	output += (nblocks * HKDS_KECCAK_256_RATE);
	outlen -= (nblocks * HKDS_KECCAK_256_RATE);

	if (outlen != 0)
	{
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_256, hash, 1);
		utils_memory_copy(output, hash, outlen);
	}

	hkds_keccak_dispose(&ctx);
}

void hkds_shake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / HKDS_KECCAK_512_RATE;
	hkds_keccak_state ctx;
	uint8_t hash[HKDS_KECCAK_512_RATE] = { 0 };

	hkds_shake_initialize(&ctx, hkds_keccak_rate_512, key, keylen);
	hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_512, output, nblocks);
	output += (nblocks * HKDS_KECCAK_512_RATE);
	outlen -= (nblocks * HKDS_KECCAK_512_RATE);

	if (outlen != 0)
	{
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_512, hash, 1);
		utils_memory_copy(output, hash, outlen);
	}

	hkds_keccak_dispose(&ctx);
}

void hkds_shake_initialize(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* key, size_t keylen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	hkds_keccak_initialize_state(ctx);
	hkds_keccak_absorb(ctx, rate, key, keylen, HKDS_KECCAK_SHAKE_DOMAIN_ID, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

void hkds_shake_squeezeblocks(hkds_keccak_state* ctx, hkds_keccak_rate rate, uint8_t* output, size_t nblocks)
{
	assert(ctx != NULL);
	assert(output != NULL);

	hkds_keccak_squeezeblocks(ctx, output, nblocks, rate, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

/* KMAC */

void hkds_kmac128_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	hkds_keccak_state ctx;

	hkds_kmac_initialize(&ctx, hkds_keccak_rate_128, key, keylen, custom, custlen);
	hkds_kmac_update(&ctx, hkds_keccak_rate_128, message, msglen);
	hkds_kmac_finalize(&ctx, hkds_keccak_rate_128, output, outlen);
}

void hkds_kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	hkds_keccak_state ctx;

	hkds_kmac_initialize(&ctx, hkds_keccak_rate_256, key, keylen, custom, custlen);
	hkds_kmac_update(&ctx, hkds_keccak_rate_256, message, msglen);
	hkds_kmac_finalize(&ctx, hkds_keccak_rate_256, output, outlen);
}

void hkds_kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	hkds_keccak_state ctx;

	hkds_kmac_initialize(&ctx, hkds_keccak_rate_512, key, keylen, custom, custlen);
	hkds_kmac_update(&ctx, hkds_keccak_rate_512, message, msglen);
	hkds_kmac_finalize(&ctx, hkds_keccak_rate_512, output, outlen);
}

void hkds_kmac_finalize(hkds_keccak_state* ctx, hkds_keccak_rate rate, uint8_t* output, size_t outlen)
{
	hkds_keccak_finalize(ctx, rate, output, outlen, HKDS_KECCAK_KMAC_DOMAIN_ID, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

void hkds_kmac_initialize(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	const uint8_t name[4] = { 0x4B, 0x4D, 0x41, 0x43 };

	hkds_keccak_absorb_key_custom(ctx, rate, key, keylen, custom, custlen, name, sizeof(name), HKDS_KECCAK_PERMUTATION_ROUNDS);
}

void hkds_kmac_update(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	hkds_keccak_update(ctx, rate, message, msglen, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

/* parallel SHAKE x4 */

#if defined(SYSTEM_HAS_AVX2)

void hkds_keccakx4_absorb(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen, uint8_t domain)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);

	__m256i t;
	__m256i idx = { 0 };
	int64_t p0;
	int64_t p1;
	int64_t p2;
	int64_t p3;
	size_t pos;
	size_t i;

	pos = 0;
	p0 = (int64_t)inp0;
	p1 = (int64_t)inp1;
	p2 = (int64_t)inp2;
	p3 = (int64_t)inp3;

	idx = _mm256_set_epi64x(p3, p2, p1, p0);

	while (inplen >= (size_t)rate)
	{
		for (i = 0; i < (size_t)rate / sizeof(uint64_t); ++i)
		{
			t = _mm256_i64gather_epi64((long long*)pos, idx, 1);
			state[i] = _mm256_xor_si256(state[i], t);
			pos += sizeof(uint64_t);
		}

		hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		inplen -= rate;
	}

	i = 0;

	while (inplen >= sizeof(uint64_t))
	{
		t = _mm256_i64gather_epi64((long long*)pos, idx, 1);
		state[i] = _mm256_xor_si256(state[i], t);

		i++;
		pos += sizeof(uint64_t);
		inplen -= sizeof(uint64_t);
	}

	if (inplen != 0)
	{
		t = _mm256_i64gather_epi64((long long*)pos, idx, 1);
		idx = _mm256_set1_epi64x((1ULL << (sizeof(uint64_t) * inplen)) - 1);
		t = _mm256_and_si256(t, idx);
		state[i] = _mm256_xor_si256(state[i], t);
	}

	t = _mm256_set1_epi64x((int64_t)domain << (sizeof(uint64_t) * inplen));
	state[i] = _mm256_xor_si256(state[i], t);
	t = _mm256_set1_epi64x(1ULL << 63);
	state[(rate / sizeof(uint64_t)) - 1] = _mm256_xor_si256(state[(rate / sizeof(uint64_t)) - 1], t);
}

void hkds_keccakx4_squeezeblocks(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t nblocks)
{
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);

	uint64_t f0;
	uint64_t f1;
	uint64_t f2;
	uint64_t f3;

	while (nblocks > 0)
	{
		hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

		for (size_t i = 0; i < (size_t)rate / sizeof(uint64_t); ++i)
		{
#if defined(SYSTEM_ISWIN64)
			f0 = _mm256_extract_epi64(state[i], 0);
			f1 = _mm256_extract_epi64(state[i], 1);
			f2 = _mm256_extract_epi64(state[i], 2);
			f3 = _mm256_extract_epi64(state[i], 3);
#else
			f0 = (uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 0) | ((uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 1) << 32);
			f1 = (uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 2) | ((uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 3) << 32);
			f2 = (uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 4) | ((uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 5) << 32);
			f3 = (uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 6) | ((uint64_t)(uint32_t)_mm256_extract_epi32(state[i], 7) << 32);
#endif
			utils_integer_le64to8(out0, f0);
			utils_integer_le64to8(out1, f1);
			utils_integer_le64to8(out2, f2);
			utils_integer_le64to8(out3, f3);

			out0 += sizeof(uint64_t);
			out1 += sizeof(uint64_t);
			out2 += sizeof(uint64_t);
			out3 += sizeof(uint64_t);
		}

		--nblocks;
	}
}

#endif

#if defined(SYSTEM_HAS_AVX512)

#define _mm512_extract_epi64x(b, i) ( \
        _mm_extract_epi64(_mm512_extracti64x2_epi64(b, i / 2), i % 2))

void hkds_keccakx8_absorb(__m512i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen, uint8_t domain)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);
	assert(inp4 != NULL);
	assert(inp5 != NULL);
	assert(inp6 != NULL);
	assert(inp7 != NULL);

	__m512i t;
	__m512i idx;
	int64_t p0;
	int64_t p1;
	int64_t p2;
	int64_t p3;
	int64_t p4;
	int64_t p5;
	int64_t p6;
	int64_t p7;
	size_t i;
	size_t pos;

	pos = 0;
	p0 = (int64_t)inp0;
	p1 = (int64_t)inp1;
	p2 = (int64_t)inp2;
	p3 = (int64_t)inp3;
	p4 = (int64_t)inp4;
	p5 = (int64_t)inp5;
	p6 = (int64_t)inp6;
	p7 = (int64_t)inp7;

	idx = _mm512_set_epi64(p7, p6, p5, p4, p3, p2, p1, p0);

	while (inplen >= (size_t)rate)
	{
		for (i = 0; i < (size_t)rate / sizeof(uint64_t); ++i)
		{
			t = _mm512_i64gather_epi64(idx, (int64_t*)pos, 1);
			state[i] = _mm512_xor_si512(state[i], t);
			pos += sizeof(uint64_t);
		}

		hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		inplen -= rate;
	}

	i = 0;

	while (inplen >= sizeof(uint64_t))
	{
		t = _mm512_i64gather_epi64(idx, (int64_t*)pos, 1);
		state[i] = _mm512_xor_si512(state[i], t);

		i++;
		pos += sizeof(uint64_t);
		inplen -= sizeof(uint64_t);
	}

	if (inplen != 0)
	{
		t = _mm512_i64gather_epi64(idx, (int64_t*)pos, 1);
		idx = _mm512_set1_epi64((1ULL << (sizeof(uint64_t) * inplen)) - 1);
		t = _mm512_and_si512(t, idx);
		state[i] = _mm512_xor_si512(state[i], t);
	}

	t = _mm512_set1_epi64((int64_t)domain << (sizeof(uint64_t) * inplen));
	state[i] = _mm512_xor_si512(state[i], t);
	t = _mm512_set1_epi64(1ULL << 63);
	state[(rate / sizeof(uint64_t)) - 1] = _mm512_xor_si512(state[(rate / sizeof(uint64_t)) - 1], t);
}

void hkds_keccakx8_squeezeblocks(__m512i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, uint8_t* out4,
	uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t nblocks)
{
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(out4 != NULL);
	assert(out5 != NULL);
	assert(out6 != NULL);
	assert(out7 != NULL);

	__m128i x;
	uint64_t f0;
	uint64_t f1;
	uint64_t f2;
	uint64_t f3;
	uint64_t f4;
	uint64_t f5;
	uint64_t f6;
	uint64_t f7;
	size_t i;

	while (nblocks > 0)
	{
		hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

		for (i = 0; i < (size_t)rate / sizeof(uint64_t); ++i)
		{
#if defined(SYSTEM_ISWIN64)
			x = _mm512_extracti64x2_epi64(state[i], 0);
			f0 = _mm_extract_epi64(x, 0);
			f0 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 0) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 1) << 32;
			f1 = _mm_extract_epi64(x, 1);
			x = _mm512_extracti64x2_epi64(state[i], 1);
			f2 = _mm_extract_epi64(x, 0);
			f3 = _mm_extract_epi64(x, 1);
			x = _mm512_extracti64x2_epi64(state[i], 2);
			f4 = _mm_extract_epi64(x, 0);
			f5 = _mm_extract_epi64(x, 1);
			x = _mm512_extracti64x2_epi64(state[i], 3);
			f6 = _mm_extract_epi64(x, 0);
			f7 = _mm_extract_epi64(x, 1);
#else
			x = _mm512_extracti64x2_epi64(state[i], 0);
			f0 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 0) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 1) << 32;
			f1 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 2) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 3) << 32;
			x = _mm512_extracti64x2_epi64(state[i], 1);
			f2 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 0) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 1) << 32;
			f3 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 2) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 3) << 32;
			x = _mm512_extracti64x2_epi64(state[i], 2);
			f4 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 0) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 1) << 32;
			f5 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 2) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 3) << 32;
			x = _mm512_extracti64x2_epi64(state[i], 3);
			f6 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 0) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 1) << 32;
			f7 = (uint64_t)(uint32_t)_mm_extract_epi32(x, 2) | (uint64_t)(uint32_t)_mm_extract_epi32(x, 3) << 32;
#endif
			utils_integer_le64to8(out0, f0);
			utils_integer_le64to8(out1, f1);
			utils_integer_le64to8(out2, f2);
			utils_integer_le64to8(out3, f3);
			utils_integer_le64to8(out4, f4);
			utils_integer_le64to8(out5, f5);
			utils_integer_le64to8(out6, f6);
			utils_integer_le64to8(out7, f7);

			out0 += sizeof(uint64_t);
			out1 += sizeof(uint64_t);
			out2 += sizeof(uint64_t);
			out3 += sizeof(uint64_t);
			out4 += sizeof(uint64_t);
			out5 += sizeof(uint64_t);
			out6 += sizeof(uint64_t);
			out7 += sizeof(uint64_t);
		}

		--nblocks;
	}
}

#endif

void hkds_shake_128x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(inplen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX2)

	size_t i;
	size_t nblocks = outlen / HKDS_KECCAK_128_RATE;
	uint8_t t[4][HKDS_KECCAK_128_RATE] = { 0 };
	__m256i state[HKDS_KECCAK_STATE_SIZE] = { 0 };

	hkds_keccakx4_absorb(state, hkds_keccak_rate_128, inp0, inp1, inp2, inp3, inplen, HKDS_KECCAK_SHAKE_DOMAIN_ID);

	if (outlen >= HKDS_KECCAK_128_RATE)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_128, out0, out1, out2, out3, nblocks);

		out0 += nblocks * HKDS_KECCAK_128_RATE;
		out1 += nblocks * HKDS_KECCAK_128_RATE;
		out2 += nblocks * HKDS_KECCAK_128_RATE;
		out3 += nblocks * HKDS_KECCAK_128_RATE;
		outlen -= nblocks * HKDS_KECCAK_128_RATE;
	}

	if (outlen != 0)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_128, t[0], t[1], t[2], t[3], 1);

		for (i = 0; i < outlen; ++i)
		{
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
		}
	}

#else

	hkds_shake128_compute(out0, outlen, inp0, inplen);
	hkds_shake128_compute(out1, outlen, inp1, inplen);
	hkds_shake128_compute(out2, outlen, inp2, inplen);
	hkds_shake128_compute(out3, outlen, inp3, inplen);

#endif
}

void hkds_shake_256x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(inplen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX2)

	size_t nblocks = outlen / HKDS_KECCAK_256_RATE;
	uint8_t t[4][HKDS_KECCAK_256_RATE] = { 0 };
	__m256i state[HKDS_KECCAK_STATE_SIZE] = { 0 };

	hkds_keccakx4_absorb(state, hkds_keccak_rate_256, inp0, inp1, inp2, inp3, inplen, HKDS_KECCAK_SHAKE_DOMAIN_ID);

	if (outlen >= HKDS_KECCAK_256_RATE)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_256, out0, out1, out2, out3, nblocks);

		out0 += nblocks * HKDS_KECCAK_256_RATE;
		out1 += nblocks * HKDS_KECCAK_256_RATE;
		out2 += nblocks * HKDS_KECCAK_256_RATE;
		out3 += nblocks * HKDS_KECCAK_256_RATE;
		outlen -= nblocks * HKDS_KECCAK_256_RATE;
	}

	if (outlen != 0)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_256, t[0], t[1], t[2], t[3], 1);

		for (size_t i = 0; i < outlen; ++i)
		{
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
		}
	}

#else

	hkds_shake256_compute(out0, outlen, inp0, inplen);
	hkds_shake256_compute(out1, outlen, inp1, inplen);
	hkds_shake256_compute(out2, outlen, inp2, inplen);
	hkds_shake256_compute(out3, outlen, inp3, inplen);

#endif
}

void hkds_shake_512x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(inplen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX2)

	size_t nblocks = outlen / HKDS_KECCAK_512_RATE;
	uint8_t t[4][HKDS_KECCAK_512_RATE] = { 0 };
	__m256i state[HKDS_KECCAK_STATE_SIZE] = { 0 };

	hkds_keccakx4_absorb(state, hkds_keccak_rate_512, inp0, inp1, inp2, inp3, inplen, HKDS_KECCAK_SHAKE_DOMAIN_ID);

	if (outlen >= HKDS_KECCAK_512_RATE)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_512, out0, out1, out2, out3, nblocks);

		out0 += nblocks * HKDS_KECCAK_512_RATE;
		out1 += nblocks * HKDS_KECCAK_512_RATE;
		out2 += nblocks * HKDS_KECCAK_512_RATE;
		out3 += nblocks * HKDS_KECCAK_512_RATE;
		outlen -= nblocks * HKDS_KECCAK_512_RATE;
	}

	if (outlen != 0)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_512, t[0], t[1], t[2], t[3], 1);

		for (size_t i = 0; i < outlen; ++i)
		{
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
		}
	}

#else

	hkds_shake512_compute(out0, outlen, inp0, inplen);
	hkds_shake512_compute(out1, outlen, inp1, inplen);
	hkds_shake512_compute(out2, outlen, inp2, inplen);
	hkds_shake512_compute(out3, outlen, inp3, inplen);

#endif
}

/* parallel shake x8 */

void hkds_shake_128x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);
	assert(inp4 != NULL);
	assert(inp5 != NULL);
	assert(inp6 != NULL);
	assert(inp7 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(out4 != NULL);
	assert(out5 != NULL);
	assert(out6 != NULL);
	assert(out7 != NULL);
	assert(inplen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX512)

	size_t nblocks = outlen / HKDS_KECCAK_128_RATE;
	uint8_t t[8][HKDS_KECCAK_128_RATE] = { 0 };
	__m512i state[HKDS_KECCAK_STATE_SIZE] = { 0 };

	hkds_keccakx8_absorb(state, hkds_keccak_rate_128, inp0, inp1, inp2, inp3, inp4, inp5, inp6, inp7, inplen, HKDS_KECCAK_SHAKE_DOMAIN_ID);

	if (outlen >= HKDS_KECCAK_128_RATE)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_128, out0, out1, out2, out3, out4, out5, out6, out7, nblocks);

		out0 += nblocks * HKDS_KECCAK_128_RATE;
		out1 += nblocks * HKDS_KECCAK_128_RATE;
		out2 += nblocks * HKDS_KECCAK_128_RATE;
		out3 += nblocks * HKDS_KECCAK_128_RATE;
		out4 += nblocks * HKDS_KECCAK_128_RATE;
		out5 += nblocks * HKDS_KECCAK_128_RATE;
		out6 += nblocks * HKDS_KECCAK_128_RATE;
		out7 += nblocks * HKDS_KECCAK_128_RATE;
		outlen -= nblocks * HKDS_KECCAK_128_RATE;
	}

	if (outlen != 0)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_128, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], 1);

		for (size_t i = 0; i < outlen; ++i)
		{
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
			out4[i] = t[4][i];
			out5[i] = t[5][i];
			out6[i] = t[6][i];
			out7[i] = t[7][i];
		}
	}

#elif defined(SYSTEM_HAS_AVX2)

	hkds_shake_128x4(out0, out1, out2, out3, outlen, inp0, inp1, inp2, inp3, inplen);
	hkds_shake_128x4(out4, out5, out6, out7, outlen, inp4, inp5, inp6, inp7, inplen);

#else

	hkds_shake128_compute(out0, outlen, inp0, inplen);
	hkds_shake128_compute(out1, outlen, inp1, inplen);
	hkds_shake128_compute(out2, outlen, inp2, inplen);
	hkds_shake128_compute(out3, outlen, inp3, inplen);
	hkds_shake128_compute(out4, outlen, inp4, inplen);
	hkds_shake128_compute(out5, outlen, inp5, inplen);
	hkds_shake128_compute(out6, outlen, inp6, inplen);
	hkds_shake128_compute(out7, outlen, inp7, inplen);

#endif
}

void hkds_shake_256x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);
	assert(inp4 != NULL);
	assert(inp5 != NULL);
	assert(inp6 != NULL);
	assert(inp7 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(out4 != NULL);
	assert(out5 != NULL);
	assert(out6 != NULL);
	assert(out7 != NULL);
	assert(inplen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX512)

	size_t nblocks = outlen / HKDS_KECCAK_256_RATE;
	uint8_t t[8][HKDS_KECCAK_256_RATE] = { 0 };
	__m512i state[HKDS_KECCAK_STATE_SIZE] = { 0 };

	hkds_keccakx8_absorb(state, hkds_keccak_rate_256, inp0, inp1, inp2, inp3, inp4, inp5, inp6, inp7, inplen, HKDS_KECCAK_SHAKE_DOMAIN_ID);

	if (outlen >= HKDS_KECCAK_256_RATE)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_256, out0, out1, out2, out3, out4, out5, out6, out7, nblocks);

		out0 += nblocks * HKDS_KECCAK_256_RATE;
		out1 += nblocks * HKDS_KECCAK_256_RATE;
		out2 += nblocks * HKDS_KECCAK_256_RATE;
		out3 += nblocks * HKDS_KECCAK_256_RATE;
		out4 += nblocks * HKDS_KECCAK_256_RATE;
		out5 += nblocks * HKDS_KECCAK_256_RATE;
		out6 += nblocks * HKDS_KECCAK_256_RATE;
		out7 += nblocks * HKDS_KECCAK_256_RATE;
		outlen -= nblocks * HKDS_KECCAK_256_RATE;
	}

	if (outlen != 0)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_256, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], 1);

		for (size_t i = 0; i < outlen; ++i)
		{
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
			out4[i] = t[4][i];
			out5[i] = t[5][i];
			out6[i] = t[6][i];
			out7[i] = t[7][i];
		}
	}

#elif defined(SYSTEM_HAS_AVX2)

	hkds_shake_256x4(out0, out1, out2, out3, outlen, inp0, inp1, inp2, inp3, inplen);
	hkds_shake_256x4(out4, out5, out6, out7, outlen, inp4, inp5, inp6, inp7, inplen);

#else

	hkds_shake256_compute(out0, outlen, inp0, inplen);
	hkds_shake256_compute(out1, outlen, inp1, inplen);
	hkds_shake256_compute(out2, outlen, inp2, inplen);
	hkds_shake256_compute(out3, outlen, inp3, inplen);
	hkds_shake256_compute(out4, outlen, inp4, inplen);
	hkds_shake256_compute(out5, outlen, inp5, inplen);
	hkds_shake256_compute(out6, outlen, inp6, inplen);
	hkds_shake256_compute(out7, outlen, inp7, inplen);

#endif
}

void hkds_shake_512x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen)
{
	assert(inp0 != NULL);
	assert(inp1 != NULL);
	assert(inp2 != NULL);
	assert(inp3 != NULL);
	assert(inp4 != NULL);
	assert(inp5 != NULL);
	assert(inp6 != NULL);
	assert(inp7 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(out4 != NULL);
	assert(out5 != NULL);
	assert(out6 != NULL);
	assert(out7 != NULL);
	assert(inplen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX512)

	size_t nblocks = outlen / HKDS_KECCAK_512_RATE;
	uint8_t t[8][HKDS_KECCAK_512_RATE] = { 0 };
	__m512i state[HKDS_KECCAK_STATE_SIZE] = { 0 };

	hkds_keccakx8_absorb(state, hkds_keccak_rate_512, inp0, inp1, inp2, inp3, inp4, inp5, inp6, inp7, inplen, HKDS_KECCAK_SHAKE_DOMAIN_ID);

	if (outlen >= HKDS_KECCAK_512_RATE)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_512, out0, out1, out2, out3, out4, out5, out6, out7, nblocks);

		out0 += nblocks * HKDS_KECCAK_512_RATE;
		out1 += nblocks * HKDS_KECCAK_512_RATE;
		out2 += nblocks * HKDS_KECCAK_512_RATE;
		out3 += nblocks * HKDS_KECCAK_512_RATE;
		out4 += nblocks * HKDS_KECCAK_512_RATE;
		out5 += nblocks * HKDS_KECCAK_512_RATE;
		out6 += nblocks * HKDS_KECCAK_512_RATE;
		out7 += nblocks * HKDS_KECCAK_512_RATE;
		outlen -= nblocks * HKDS_KECCAK_512_RATE;
	}

	if (outlen != 0)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_512, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], 1);

		for (size_t i = 0; i < outlen; ++i)
		{
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
			out4[i] = t[4][i];
			out5[i] = t[5][i];
			out6[i] = t[6][i];
			out7[i] = t[7][i];
		}
	}

#elif defined(SYSTEM_HAS_AVX2)

	hkds_shake_512x4(out0, out1, out2, out3, outlen, inp0, inp1, inp2, inp3, inplen);
	hkds_shake_512x4(out4, out5, out6, out7, outlen, inp4, inp5, inp6, inp7, inplen);

#else

	hkds_shake512_compute(out0, outlen, inp0, inplen);
	hkds_shake512_compute(out1, outlen, inp1, inplen);
	hkds_shake512_compute(out2, outlen, inp2, inplen);
	hkds_shake512_compute(out3, outlen, inp3, inplen);
	hkds_shake512_compute(out4, outlen, inp4, inplen);
	hkds_shake512_compute(out5, outlen, inp5, inplen);
	hkds_shake512_compute(out6, outlen, inp6, inplen);
	hkds_shake512_compute(out7, outlen, inp7, inplen);

#endif
}

/* parallel kmac x4 */

#if defined(SYSTEM_HAS_AVX2)

static void kmacx4_fast_absorb(__m256i state[HKDS_KECCAK_STATE_SIZE], const uint8_t* inp0, const uint8_t* inp1,
	const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	__m256i t;
	uint64_t tmps[4] = { 0 };
	size_t pos;

	pos = 0;

	for (size_t i = 0; i < inplen / sizeof(uint64_t); ++i)
	{
		tmps[0] = utils_integer_le8to64(inp0 + pos);
		tmps[1] = utils_integer_le8to64(inp1 + pos);
		tmps[2] = utils_integer_le8to64(inp2 + pos);
		tmps[3] = utils_integer_le8to64(inp3 + pos);

		t = _mm256_loadu_si256((const __m256i*)tmps);
		state[i] = _mm256_xor_si256(state[i], t);
		pos += 8;
	}
}

static void kmacx4_customize(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* name, size_t nmelen)
{
	uint8_t pad[4][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t oft;
	size_t i;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad[0], (size_t)rate);
	oft += keccak_left_encode((pad[0] + oft), nmelen * 8);

	for (i = 0; i < nmelen; ++i)
	{
		pad[0][oft + i] = name[i];
	}

	oft += nmelen;
	oft += keccak_left_encode((pad[0] + oft), cstlen * 8);
	utils_memory_copy(pad[1], pad[0], oft);
	utils_memory_copy(pad[2], pad[0], oft);
	utils_memory_copy(pad[3], pad[0], oft);

	for (i = 0; i < cstlen; ++i)
	{
		if (oft == rate)
		{
			kmacx4_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], (size_t)rate);
			hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0;
		}

		pad[0][oft] = cst0[i];
		pad[1][oft] = cst1[i];
		pad[2][oft] = cst2[i];
		pad[3][oft] = cst3[i];
		++oft;
	}

	kmacx4_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

	/* stage 2: key */

	utils_memory_clear(pad[0], oft);
	utils_memory_clear(pad[1], oft);
	utils_memory_clear(pad[2], oft);
	utils_memory_clear(pad[3], oft);

	oft = keccak_left_encode(pad[0], (size_t)rate);
	oft += keccak_left_encode((pad[0] + oft), keylen * 8);
	utils_memory_copy(pad[1], pad[0], oft);
	utils_memory_copy(pad[2], pad[0], oft);
	utils_memory_copy(pad[3], pad[0], oft);

	for (i = 0; i < keylen; ++i)
	{
		if (oft == rate)
		{
			kmacx4_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], (size_t)rate);
			hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0;
		}

		pad[0][oft] = key0[i];
		pad[1][oft] = key1[i];
		pad[2][oft] = key2[i];
		pad[3][oft] = key3[i];
		++oft;
	}

	utils_memory_clear((pad[0] + oft), (size_t)rate - oft);
	utils_memory_clear((pad[1] + oft), (size_t)rate - oft);
	utils_memory_clear((pad[2] + oft), (size_t)rate - oft);
	utils_memory_clear((pad[3] + oft), (size_t)rate - oft);

	kmacx4_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

static void kmacx4_finalize(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen)
{
	uint8_t tmps[4][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[4][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	const size_t BLKCNT = outlen / (size_t)rate;
	size_t bitlen;
	size_t i;
	size_t pos;

	pos = 0;

	while (msglen >= (size_t)rate)
	{
		kmacx4_fast_absorb(state, (msg0 + pos), (msg1 + pos), (msg2 + pos), (msg3 + pos), (size_t)rate);
		hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos += (size_t)rate;
		msglen -= (size_t)rate;
	}

	if (msglen > 0)
	{
		utils_memory_copy(pad[0], (msg0 + pos), msglen);
		utils_memory_copy(pad[1], (msg1 + pos), msglen);
		utils_memory_copy(pad[2], (msg2 + pos), msglen);
		utils_memory_copy(pad[3], (msg3 + pos), msglen);
	}

	pos = msglen;
	bitlen = keccak_right_encode(buf, outlen * 8);

	if (pos + bitlen >= (size_t)rate)
	{
		kmacx4_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], (size_t)rate);
		hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos = 0;
	}

	utils_memory_copy((pad[0] + pos), buf, bitlen);
	pad[0][pos + bitlen] = HKDS_KECCAK_KMAC_DOMAIN_ID;
	pad[0][rate - 1] |= 128U;
	utils_memory_copy((pad[1] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[2] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[3] + pos), (pad[0] + pos), (size_t)rate - pos);

	kmacx4_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], (size_t)rate);

	if (outlen > (size_t)rate)
	{
		hkds_keccakx4_squeezeblocks(state, rate, out0, out1, out2, out3, BLKCNT);

		out0 += BLKCNT * (size_t)rate;
		out1 += BLKCNT * (size_t)rate;
		out2 += BLKCNT * (size_t)rate;
		out3 += BLKCNT * (size_t)rate;
		outlen -= BLKCNT * (size_t)rate;
	}

	if (outlen != 0)
	{
		hkds_keccakx4_squeezeblocks(state, rate, tmps[0], tmps[1], tmps[2], tmps[3], 1);

		for (i = 0; i < outlen; ++i)
		{
			out0[i] = tmps[0][i];
			out1[i] = tmps[1][i];
			out2[i] = tmps[2][i];
			out3[i] = tmps[3][i];
		}
	}
}

#endif

void hkds_kmac_128x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen)
{
	assert(key0 != NULL);
	assert(key1 != NULL);
	assert(key2 != NULL);
	assert(key3 != NULL);
	assert(msg0 != NULL);
	assert(msg1 != NULL);
	assert(msg2 != NULL);
	assert(msg3 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(keylen != 0);
	assert(msglen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX2)

	__m256i state[HKDS_KECCAK_STATE_SIZE] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };

	kmacx4_customize(state, hkds_keccak_rate_128, key0, key1, key2, key3, keylen, cst0, cst1, cst2, cst3, cstlen, name, sizeof(name));
	kmacx4_finalize(state, hkds_keccak_rate_128, msg0, msg1, msg2, msg3, msglen, out0, out1, out2, out3, outlen);

#else

	hkds_kmac128_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
	hkds_kmac128_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
	hkds_kmac128_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
	hkds_kmac128_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);

#endif
}

void hkds_kmac_256x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen)
{
	assert(key0 != NULL);
	assert(key1 != NULL);
	assert(key2 != NULL);
	assert(key3 != NULL);
	assert(msg0 != NULL);
	assert(msg1 != NULL);
	assert(msg2 != NULL);
	assert(msg3 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(keylen != 0);
	assert(msglen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX2)

	__m256i state[HKDS_KECCAK_STATE_SIZE] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };

	kmacx4_customize(state, hkds_keccak_rate_256, key0, key1, key2, key3, keylen, cst0, cst1, cst2, cst3, cstlen, name, sizeof(name));
	kmacx4_finalize(state, hkds_keccak_rate_256, msg0, msg1, msg2, msg3, msglen, out0, out1, out2, out3, outlen);

#else

	hkds_kmac256_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
	hkds_kmac256_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
	hkds_kmac256_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
	hkds_kmac256_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);

#endif
}

void hkds_kmac_512x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen)
{
	assert(key0 != NULL);
	assert(key1 != NULL);
	assert(key2 != NULL);
	assert(key3 != NULL);
	assert(msg0 != NULL);
	assert(msg1 != NULL);
	assert(msg2 != NULL);
	assert(msg3 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(keylen != 0);
	assert(msglen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX2)

	__m256i state[HKDS_KECCAK_STATE_SIZE] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };

	kmacx4_customize(state, hkds_keccak_rate_512, key0, key1, key2, key3, keylen, cst0, cst1, cst2, cst3, cstlen, name, sizeof(name));
	kmacx4_finalize(state, hkds_keccak_rate_512, msg0, msg1, msg2, msg3, msglen, out0, out1, out2, out3, outlen);

#else

	hkds_kmac512_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
	hkds_kmac512_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
	hkds_kmac512_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
	hkds_kmac512_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);

#endif
}

/* parallel kmac x8 */

#if defined(SYSTEM_HAS_AVX512)

static void kmacx8_fast_absorb(__m512i state[HKDS_KECCAK_STATE_SIZE],
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7,
	size_t inplen)
{
	__m512i t;
	uint64_t tmps[8] = { 0 };
	size_t pos;

	pos = 0;

	for (size_t i = 0; i < inplen / sizeof(uint64_t); ++i)
	{
		tmps[0] = utils_integer_le8to64((inp0 + pos));
		tmps[1] = utils_integer_le8to64((inp1 + pos));
		tmps[2] = utils_integer_le8to64((inp2 + pos));
		tmps[3] = utils_integer_le8to64((inp3 + pos));
		tmps[4] = utils_integer_le8to64((inp4 + pos));
		tmps[5] = utils_integer_le8to64((inp5 + pos));
		tmps[6] = utils_integer_le8to64((inp6 + pos));
		tmps[7] = utils_integer_le8to64((inp7 + pos));

		t = _mm512_loadu_si512((const __m512i*)tmps);
		state[i] = _mm512_xor_si512(state[i], t);
		pos += 8;
	}
}

static void kmacx8_customize(__m512i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* name, size_t nmelen)
{
	uint8_t pad[8][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t oft;
	size_t i;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad[0], rate);
	oft += keccak_left_encode((pad[0] + oft), nmelen * 8);

	for (i = 0; i < nmelen; ++i)
	{
		pad[0][oft + i] = name[i];
	}

	oft += nmelen;
	oft += keccak_left_encode((pad[0] + oft), cstlen * 8);
	utils_memory_copy(pad[1], pad[0], oft);
	utils_memory_copy(pad[2], pad[0], oft);
	utils_memory_copy(pad[3], pad[0], oft);
	utils_memory_copy(pad[4], pad[0], oft);
	utils_memory_copy(pad[5], pad[0], oft);
	utils_memory_copy(pad[6], pad[0], oft);
	utils_memory_copy(pad[7], pad[0], oft);

	for (i = 0; i < cstlen; ++i)
	{
		if (oft == rate)
		{
			kmacx8_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], pad[4], pad[5], pad[6], pad[7], (size_t)rate);
			hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0;
		}

		pad[0][oft] = cst0[i];
		pad[1][oft] = cst1[i];
		pad[2][oft] = cst2[i];
		pad[3][oft] = cst3[i];
		pad[4][oft] = cst4[i];
		pad[5][oft] = cst5[i];
		pad[6][oft] = cst6[i];
		pad[7][oft] = cst7[i];
		++oft;
	}

	kmacx8_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], pad[4], pad[5], pad[6], pad[7], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

	/* stage 2: key */

	utils_memory_clear(pad[0], oft);
	utils_memory_clear(pad[1], oft);
	utils_memory_clear(pad[2], oft);
	utils_memory_clear(pad[3], oft);
	utils_memory_clear(pad[4], oft);
	utils_memory_clear(pad[5], oft);
	utils_memory_clear(pad[6], oft);
	utils_memory_clear(pad[7], oft);

	oft = keccak_left_encode(pad[0], rate);
	oft += keccak_left_encode((pad[0] + oft), keylen * 8);
	utils_memory_copy(pad[1], pad[0], oft);
	utils_memory_copy(pad[2], pad[0], oft);
	utils_memory_copy(pad[3], pad[0], oft);
	utils_memory_copy(pad[4], pad[0], oft);
	utils_memory_copy(pad[5], pad[0], oft);
	utils_memory_copy(pad[6], pad[0], oft);
	utils_memory_copy(pad[7], pad[0], oft);

	for (i = 0; i < keylen; ++i)
	{
		if (oft == rate)
		{
			kmacx8_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], pad[4], pad[5], pad[6], pad[7], rate);
			hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0;
		}

		pad[0][oft] = key0[i];
		pad[1][oft] = key1[i];
		pad[2][oft] = key2[i];
		pad[3][oft] = key3[i];
		pad[4][oft] = key4[i];
		pad[5][oft] = key5[i];
		pad[6][oft] = key6[i];
		pad[7][oft] = key7[i];
		++oft;
	}

	kmacx8_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], pad[4], pad[5], pad[6], pad[7], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

static void kmacx8_finalize(__m512i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen)
{
	uint8_t tmps[8][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[8][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0 };
	const size_t BLKCNT = outlen / (size_t)rate;
	size_t bitlen;
	size_t i;
	size_t pos;

	pos = 0;

	while (msglen >= (size_t)rate)
	{
		kmacx8_fast_absorb(state, (msg0 + pos), (msg1 + pos), (msg2 + pos), (msg3 + pos),
			(msg4 + pos), (msg5 + pos), (msg6 + pos), (msg7 + pos), (size_t)rate);

		hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos += (size_t)rate;
		msglen -= (size_t)rate;
	}

	if (msglen > 0)
	{
		utils_memory_copy(pad[0], (msg0 + pos), msglen);
		utils_memory_copy(pad[1], (msg1 + pos), msglen);
		utils_memory_copy(pad[2], (msg2 + pos), msglen);
		utils_memory_copy(pad[3], (msg3 + pos), msglen);
		utils_memory_copy(pad[4], (msg4 + pos), msglen);
		utils_memory_copy(pad[5], (msg5 + pos), msglen);
		utils_memory_copy(pad[6], (msg6 + pos), msglen);
		utils_memory_copy(pad[7], (msg7 + pos), msglen);
	}

	pos = msglen;
	bitlen = keccak_right_encode(buf, outlen * 8);

	if (pos + bitlen >= (size_t)rate)
	{
		kmacx8_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], pad[4], pad[5], pad[6], pad[7], (size_t)rate);
		hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos = 0;
	}

	utils_memory_copy((pad[0] + pos), buf, bitlen);
	pad[0][pos + bitlen] = HKDS_KECCAK_KMAC_DOMAIN_ID;
	pad[0][rate - 1] |= 128U;

	utils_memory_copy((pad[1] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[2] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[3] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[4] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[5] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[6] + pos), (pad[0] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[7] + pos), (pad[0] + pos), (size_t)rate - pos);

	kmacx8_fast_absorb(state, pad[0], pad[1], pad[2], pad[3], pad[4], pad[5], pad[6], pad[7], (size_t)rate);

	if (outlen > (size_t)rate)
	{
		hkds_keccakx8_squeezeblocks(state, rate, out0, out1, out2, out3, out4, out5, out6, out7, BLKCNT);

		out0 += BLKCNT * (size_t)rate;
		out1 += BLKCNT * (size_t)rate;
		out2 += BLKCNT * (size_t)rate;
		out3 += BLKCNT * (size_t)rate;
		out4 += BLKCNT * (size_t)rate;
		out5 += BLKCNT * (size_t)rate;
		out6 += BLKCNT * (size_t)rate;
		out7 += BLKCNT * (size_t)rate;
		outlen -= BLKCNT * (size_t)rate;
	}

	if (outlen != 0)
	{
		hkds_keccakx8_squeezeblocks(state, rate, tmps[0], tmps[1], tmps[2], tmps[3], tmps[4], tmps[5], tmps[6], tmps[7], 1);

		for (i = 0; i < outlen; ++i)
		{
			out0[i] = tmps[0][i];
			out1[i] = tmps[1][i];
			out2[i] = tmps[2][i];
			out3[i] = tmps[3][i];
			out4[i] = tmps[4][i];
			out5[i] = tmps[5][i];
			out6[i] = tmps[6][i];
			out7[i] = tmps[7][i];
		}
	}
}

#endif

void hkds_kmac_128x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen)
{
	assert(key0 != NULL);
	assert(key1 != NULL);
	assert(key2 != NULL);
	assert(key3 != NULL);
	assert(key4 != NULL);
	assert(key5 != NULL);
	assert(key6 != NULL);
	assert(key7 != NULL);
	assert(msg0 != NULL);
	assert(msg1 != NULL);
	assert(msg2 != NULL);
	assert(msg3 != NULL);
	assert(msg4 != NULL);
	assert(msg5 != NULL);
	assert(msg6 != NULL);
	assert(msg7 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(out4 != NULL);
	assert(out5 != NULL);
	assert(out6 != NULL);
	assert(out7 != NULL);
	assert(keylen != 0);
	assert(msglen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX512)

	__m512i state[HKDS_KECCAK_STATE_SIZE] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };

	kmacx8_customize(state, hkds_keccak_rate_128, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
		cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
	kmacx8_finalize(state, hkds_keccak_rate_128, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
		out0, out1, out2, out3, out4, out5, out6, out7, outlen);

#elif defined(SYSTEM_HAS_AVX2)

	hkds_kmac_128x4(out0, out1, out2, out3, outlen, key0, key1, key2, key3, keylen,
		cst0, cst1, cst2, cst3, cstlen, msg0, msg1, msg2, msg3, msglen);
	hkds_kmac_128x4(out4, out5, out6, out7, outlen, key4, key5, key6, key7, keylen,
		cst4, cst5, cst6, cst7, cstlen, msg4, msg5, msg6, msg7, msglen);

#else

	hkds_kmac128_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
	hkds_kmac128_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
	hkds_kmac128_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
	hkds_kmac128_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);
	hkds_kmac128_compute(out4, outlen, msg4, msglen, key4, keylen, cst4, cstlen);
	hkds_kmac128_compute(out5, outlen, msg5, msglen, key5, keylen, cst5, cstlen);
	hkds_kmac128_compute(out6, outlen, msg6, msglen, key6, keylen, cst6, cstlen);
	hkds_kmac128_compute(out7, outlen, msg7, msglen, key7, keylen, cst7, cstlen);

#endif
}

void hkds_kmac_256x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen)
{
	assert(key0 != NULL);
	assert(key1 != NULL);
	assert(key2 != NULL);
	assert(key3 != NULL);
	assert(key4 != NULL);
	assert(key5 != NULL);
	assert(key6 != NULL);
	assert(key7 != NULL);
	assert(msg0 != NULL);
	assert(msg1 != NULL);
	assert(msg2 != NULL);
	assert(msg3 != NULL);
	assert(msg4 != NULL);
	assert(msg5 != NULL);
	assert(msg6 != NULL);
	assert(msg7 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(out4 != NULL);
	assert(out5 != NULL);
	assert(out6 != NULL);
	assert(out7 != NULL);
	assert(keylen != 0);
	assert(msglen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX512)

	__m512i state[HKDS_KECCAK_STATE_SIZE] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };

	kmacx8_customize(state, hkds_keccak_rate_256, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
		cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
	kmacx8_finalize(state, hkds_keccak_rate_256, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
		out0, out1, out2, out3, out4, out5, out6, out7, outlen);

#elif defined(SYSTEM_HAS_AVX2)

	hkds_kmac_256x4(out0, out1, out2, out3, outlen, key0, key1, key2, key3, keylen,
		cst0, cst1, cst2, cst3, cstlen, msg0, msg1, msg2, msg3, msglen);
	hkds_kmac_256x4(out4, out5, out6, out7, outlen, key4, key5, key6, key7, keylen,
		cst4, cst5, cst6, cst7, cstlen, msg4, msg5, msg6, msg7, msglen);

#else

	hkds_kmac256_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
	hkds_kmac256_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
	hkds_kmac256_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
	hkds_kmac256_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);
	hkds_kmac256_compute(out4, outlen, msg4, msglen, key4, keylen, cst4, cstlen);
	hkds_kmac256_compute(out5, outlen, msg5, msglen, key5, keylen, cst5, cstlen);
	hkds_kmac256_compute(out6, outlen, msg6, msglen, key6, keylen, cst6, cstlen);
	hkds_kmac256_compute(out7, outlen, msg7, msglen, key7, keylen, cst7, cstlen);

#endif
}

void hkds_kmac_512x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen)
{
	assert(key0 != NULL);
	assert(key1 != NULL);
	assert(key2 != NULL);
	assert(key3 != NULL);
	assert(key4 != NULL);
	assert(key5 != NULL);
	assert(key6 != NULL);
	assert(key7 != NULL);
	assert(msg0 != NULL);
	assert(msg1 != NULL);
	assert(msg2 != NULL);
	assert(msg3 != NULL);
	assert(msg4 != NULL);
	assert(msg5 != NULL);
	assert(msg6 != NULL);
	assert(msg7 != NULL);
	assert(out0 != NULL);
	assert(out1 != NULL);
	assert(out2 != NULL);
	assert(out3 != NULL);
	assert(out4 != NULL);
	assert(out5 != NULL);
	assert(out6 != NULL);
	assert(out7 != NULL);
	assert(keylen != 0);
	assert(msglen != 0);
	assert(outlen != 0);

#if defined(SYSTEM_HAS_AVX512)

	__m512i state[HKDS_KECCAK_STATE_SIZE] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };

	kmacx8_customize(state, hkds_keccak_rate_512, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
		cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
	kmacx8_finalize(state, hkds_keccak_rate_512, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
		out0, out1, out2, out3, out4, out5, out6, out7, outlen);

#elif defined(SYSTEM_HAS_AVX2)

	hkds_kmac_512x4(out0, out1, out2, out3, outlen, key0, key1, key2, key3, keylen,
		cst0, cst1, cst2, cst3, cstlen, msg0, msg1, msg2, msg3, msglen);
	hkds_kmac_512x4(out4, out5, out6, out7, outlen, key4, key5, key6, key7, keylen,
		cst4, cst5, cst6, cst7, cstlen, msg4, msg5, msg6, msg7, msglen);

#else

	hkds_kmac512_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
	hkds_kmac512_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
	hkds_kmac512_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
	hkds_kmac512_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);
	hkds_kmac512_compute(out4, outlen, msg4, msglen, key4, keylen, cst4, cstlen);
	hkds_kmac512_compute(out5, outlen, msg5, msglen, key5, keylen, cst5, cstlen);
	hkds_kmac512_compute(out6, outlen, msg6, msglen, key6, keylen, cst6, cstlen);
	hkds_kmac512_compute(out7, outlen, msg7, msglen, key7, keylen, cst7, cstlen);

#endif
}
