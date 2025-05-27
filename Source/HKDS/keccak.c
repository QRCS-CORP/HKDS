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
#if defined(HKDS_SYSTEM_IS_LITTLE_ENDIAN)
	utils_memory_xor((uint8_t*)state, message, msglen);
#else
	for (size_t i = 0U; i < msglen / sizeof(uint64_t); ++i)
	{
		state[i] ^= utils_integer_le8to64((message + (sizeof(uint64_t) * i)));
	}
#endif
}

static size_t keccak_left_encode(uint8_t* buffer, size_t value)
{
	size_t n;
	size_t v;

	for (v = value, n = 0U; v != 0U && n < sizeof(size_t); ++n, v >>= 8U) { /* increments n */ }

	if (n == 0U)
	{
		n = 1U;
	}

	for (size_t i = 1U; i <= n; ++i)
	{
		buffer[i] = (uint8_t)(value >> (8U * (n - i)));
	}

	buffer[0U] = (uint8_t)n;

	return n + 1U;
}

static size_t keccak_right_encode(uint8_t* buffer, size_t value)
{
	size_t n;
	size_t v;

	for (v = value, n = 0U; v != 0U && (n < sizeof(size_t)); ++n, v >>= 8U) { /* increments n */ }

	if (n == 0U)
	{
		n = 1U;
	}

	for (size_t i = 1U; i <= n; ++i)
	{
		buffer[i - 1U] = (uint8_t)(value >> (8U * (n - i)));
	}

	buffer[n] = (uint8_t)n;

	return n + 1U;
}

#if defined(HKDS_SYSTEM_HAS_AVX512)

static void hkds_keccak_permute_p8x1600(__m512i state[HKDS_KECCAK_STATE_SIZE], size_t rounds)
{
	HKDS_ASSERT(rounds % 2U == 0U);

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

	a0 = state[0U];
	a1 = state[1U];
	a2 = state[2U];
	a3 = state[3U];
	a4 = state[4U];
	a5 = state[5U];
	a6 = state[6U];
	a7 = state[7U];
	a8 = state[8U];
	a9 = state[9U];
	a10 = state[10U];
	a11 = state[11U];
	a12 = state[12U];
	a13 = state[13U];
	a14 = state[14U];
	a15 = state[15U];
	a16 = state[16U];
	a17 = state[17U];
	a18 = state[18U];
	a19 = state[19U];
	a20 = state[20U];
	a21 = state[21U];
	a22 = state[22U];
	a23 = state[23U];
	a24 = state[24U];

	for (i = 0U; i < rounds; i += 2U)
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
		a0 = _mm512_xor_si512(a0, _mm512_set1_epi64(KECCAK_ROUND_CONSTANTS[i + 1U]));
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

	state[0U] = a0;
	state[1U] = a1;
	state[2U] = a2;
	state[3U] = a3;
	state[4U] = a4;
	state[5U] = a5;
	state[6U] = a6;
	state[7U] = a7;
	state[8U] = a8;
	state[9U] = a9;
	state[10U] = a10;
	state[11U] = a11;
	state[12U] = a12;
	state[13U] = a13;
	state[14U] = a14;
	state[15U] = a15;
	state[16U] = a16;
	state[17U] = a17;
	state[18U] = a18;
	state[19U] = a19;
	state[20U] = a20;
	state[21U] = a21;
	state[22U] = a22;
	state[23U] = a23;
	state[24U] = a24;
}

#endif

#if defined(HKDS_SYSTEM_HAS_AVX2)

static void hkds_keccak_permute_p4x1600(__m256i state[HKDS_KECCAK_STATE_SIZE], size_t rounds)
{
	HKDS_ASSERT(rounds % 2U == 0U);

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

	a0 = state[0U];
	a1 = state[1U];
	a2 = state[2U];
	a3 = state[3U];
	a4 = state[4U];
	a5 = state[5U];
	a6 = state[6U];
	a7 = state[7U];
	a8 = state[8U];
	a9 = state[9U];
	a10 = state[10U];
	a11 = state[11U];
	a12 = state[12U];
	a13 = state[13U];
	a14 = state[14U];
	a15 = state[15U];
	a16 = state[16U];
	a17 = state[17U];
	a18 = state[18U];
	a19 = state[19U];
	a20 = state[20U];
	a21 = state[21U];
	a22 = state[22U];
	a23 = state[23U];
	a24 = state[24U];

	for (i = 0U; i < rounds; i += 2U)
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
		a0 = _mm256_xor_si256(a0, _mm256_set1_epi64x(KECCAK_ROUND_CONSTANTS[i + 1U]));
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

	state[0U] = a0;
	state[1U] = a1;
	state[2U] = a2;
	state[3U] = a3;
	state[4U] = a4;
	state[5U] = a5;
	state[6U] = a6;
	state[7U] = a7;
	state[8U] = a8;
	state[9U] = a9;
	state[10U] = a10;
	state[11U] = a11;
	state[12U] = a12;
	state[13U] = a13;
	state[14U] = a14;
	state[15U] = a15;
	state[16U] = a16;
	state[17U] = a17;
	state[18U] = a18;
	state[19U] = a19;
	state[20U] = a20;
	state[21U] = a21;
	state[22U] = a22;
	state[23U] = a23;
	state[24U] = a24;
}

#endif

/* Keccak */

void hkds_keccak_absorb(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* message, size_t msglen, uint8_t domain, size_t rounds)
{
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(message != NULL);

	HKDS_SIMD_ALIGN uint8_t msg[HKDS_KECCAK_STATE_BYTE_SIZE];

	if (ctx != NULL && message != NULL)
	{
		while (msglen >= (size_t)rate)
		{
#if defined(HKDS_SYSTEM_IS_LITTLE_ENDIAN)
			utils_memory_xor((uint8_t*)ctx->state, message, rate);
#else
			for (size_t i = 0U; i < rate / sizeof(uint64_t); ++i)
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
		utils_memory_clear((msg + msglen + 1U), rate - msglen + 1U);
		msg[rate - 1U] |= 128U;

#if defined(HKDS_SYSTEM_IS_LITTLE_ENDIAN)
		utils_memory_xor((uint8_t*)ctx->state, msg, rate);
#else
		for (size_t i = 0U; i < rate / 8; ++i)
		{
			ctx->state[i] ^= utils_integer_le8to64((msg + (8U * i)));
		}
#endif
	}
}

static void hkds_keccak_absorb_key_custom(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds)
{
	HKDS_ASSERT(ctx != NULL);

	uint8_t pad[HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	size_t oft;
	size_t i;

	utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
	utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0U;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((pad + oft), namelen * 8U);

	if (name != NULL)
	{
		for (i = 0U; i < namelen; ++i)
		{
			pad[oft + i] = name[i];
		}
	}

	oft += namelen;
	oft += keccak_left_encode((pad + oft), custlen * 8U);

	if (custom != NULL)
	{
		for (i = 0U; i < custlen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				hkds_keccak_permute(ctx, rounds);
				oft = 0U;
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
	oft += keccak_left_encode((pad + oft), keylen * 8U);

	if (key != NULL)
	{
		for (i = 0U; i < keylen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				hkds_keccak_permute(ctx, rounds);
				oft = 0U;
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
	HKDS_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0U;
	}
}

void hkds_keccak_finalize(hkds_keccak_state* ctx, hkds_keccak_rate rate, uint8_t* output, size_t outlen, uint8_t domain, size_t rounds)
{
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(output != NULL);

	HKDS_SIMD_ALIGN uint8_t buf[sizeof(size_t) + 1U] = { 0U };
	HKDS_SIMD_ALIGN uint8_t pad[HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	size_t bitlen;

	if (ctx != NULL && output != NULL)
	{
		utils_memory_copy(pad, ctx->buffer, ctx->position);
		bitlen = keccak_right_encode(buf, outlen * 8U);

		if (ctx->position + bitlen >= (size_t)rate)
		{
			keccak_fast_absorb(ctx->state, pad, ctx->position);
			hkds_keccak_permute(ctx, rounds);
			ctx->position = 0U;
		}

		utils_memory_copy((pad + ctx->position), buf, bitlen);

		pad[ctx->position + bitlen] = domain;
		pad[rate - 1U] |= 128U;
		keccak_fast_absorb(ctx->state, pad, rate);

		while (outlen >= (size_t)rate)
		{
			hkds_keccak_squeezeblocks(ctx, pad, 1U, rate, rounds);
			utils_memory_copy(output, pad, rate);
			output += rate;
			outlen -= rate;
		}

		if (outlen > 0U)
		{
			hkds_keccak_squeezeblocks(ctx, pad, 1U, rate, rounds);
			utils_memory_copy(output, pad, outlen);
		}

		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0U;
	}
}

static void hkds_keccak_permute_p1600c(uint64_t* state, size_t rounds)
{
	HKDS_ASSERT(state != NULL);
	HKDS_ASSERT(rounds % 2 == 0);

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
	Aba = state[0U];
	Abe = state[1U];
	Abi = state[2U];
	Abo = state[3U];
	Abu = state[4U];
	Aga = state[5U];
	Age = state[6U];
	Agi = state[7U];
	Ago = state[8U];
	Agu = state[9U];
	Aka = state[10U];
	Ake = state[11U];
	Aki = state[12U];
	Ako = state[13U];
	Aku = state[14U];
	Ama = state[15U];
	Ame = state[16U];
	Ami = state[17U];
	Amo = state[18U];
	Amu = state[19U];
	Asa = state[20U];
	Ase = state[21U];
	Asi = state[22U];
	Aso = state[23U];
	Asu = state[24U];

	for (size_t i = 0U; i < rounds; i += 2)
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
	state[0U] = Aba;
	state[1U] = Abe;
	state[2U] = Abi;
	state[3U] = Abo;
	state[4U] = Abu;
	state[5U] = Aga;
	state[6U] = Age;
	state[7U] = Agi;
	state[8U] = Ago;
	state[9U] = Agu;
	state[10U] = Aka;
	state[11U] = Ake;
	state[12U] = Aki;
	state[13U] = Ako;
	state[14U] = Aku;
	state[15U] = Ama;
	state[16U] = Ame;
	state[17U] = Ami;
	state[18U] = Amo;
	state[19U] = Amu;
	state[20U] = Asa;
	state[21U] = Ase;
	state[22U] = Asi;
	state[23U] = Aso;
	state[24U] = Asu;
}

static void hkds_keccak_permute_p1600u(uint64_t* state)
{
	HKDS_ASSERT(state != NULL);

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

	Aba = state[0U];
	Abe = state[1U];
	Abi = state[2U];
	Abo = state[3U];
	Abu = state[4U];
	Aga = state[5U];
	Age = state[6U];
	Agi = state[7U];
	Ago = state[8U];
	Agu = state[9U];
	Aka = state[10U];
	Ake = state[11U];
	Aki = state[12U];
	Ako = state[13U];
	Aku = state[14U];
	Ama = state[15U];
	Ame = state[16U];
	Ami = state[17U];
	Amo = state[18U];
	Amu = state[19U];
	Asa = state[20U];
	Ase = state[21U];
	Asi = state[22U];
	Aso = state[23U];
	Asu = state[24U];

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

	state[0U] = Aba;
	state[1U] = Abe;
	state[2U] = Abi;
	state[3U] = Abo;
	state[4U] = Abu;
	state[5U] = Aga;
	state[6U] = Age;
	state[7U] = Agi;
	state[8U] = Ago;
	state[9U] = Agu;
	state[10U] = Aka;
	state[11U] = Ake;
	state[12U] = Aki;
	state[13U] = Ako;
	state[14U] = Aku;
	state[15U] = Ama;
	state[16U] = Ame;
	state[17U] = Ami;
	state[18U] = Amo;
	state[19U] = Amu;
	state[20U] = Asa;
	state[21U] = Ase;
	state[22U] = Asi;
	state[23U] = Aso;
	state[24U] = Asu;
}

void hkds_keccak_permute(hkds_keccak_state* ctx, size_t rounds)
{
	HKDS_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
#if defined(HKDS_KECCAK_UNROLLED_PERMUTATION)
		hkds_keccak_permute_p1600u(ctx->state)
#else
		hkds_keccak_permute_p1600c(ctx->state, rounds);
#endif
	}
}

void hkds_keccak_squeezeblocks(hkds_keccak_state* ctx, uint8_t* output, size_t nblocks, hkds_keccak_rate rate, size_t rounds)
{
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(output != NULL);

	if (ctx != NULL && output != NULL)
	{
		while (nblocks > 0)
		{
			hkds_keccak_permute(ctx, rounds);

#if defined(HKDS_SYSTEM_IS_LITTLE_ENDIAN)
			utils_memory_copy(output, (uint8_t*)ctx->state, rate);
#else
			for (size_t i = 0U; i < (rate >> 3); ++i)
			{
				utils_integer_le64to8(output + (i * sizeof(uint64_t)), ctx->state[i]);
			}
#endif
			output += rate;
			nblocks--;
		}
	}
}

void hkds_keccak_initialize_state(hkds_keccak_state* ctx)
{
	HKDS_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		utils_memory_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		utils_memory_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0U;
	}
}

void hkds_keccak_update(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* message, size_t msglen, size_t rounds)
{
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(message != NULL);

	if (ctx != NULL && message != NULL && msglen != 0U)
	{
		if (ctx->position != 0U && (ctx->position + msglen >= (size_t)rate))
		{
			const size_t RMDLEN = rate - ctx->position;

			if (RMDLEN != 0U)
			{
				utils_memory_copy((ctx->buffer + ctx->position), message, RMDLEN);
			}

			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			hkds_keccak_permute(ctx, rounds);
			ctx->position = 0U;
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
		if (msglen != 0U)
		{
			utils_memory_copy((ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}

/* SHAKE */

void hkds_shake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(key != NULL);

	HKDS_SIMD_ALIGN uint8_t hash[HKDS_KECCAK_128_RATE] = { 0U };
	const size_t nblocks = outlen / HKDS_KECCAK_128_RATE;
	hkds_keccak_state ctx;

	if (output != NULL && key != NULL)
	{
		hkds_shake_initialize(&ctx, hkds_keccak_rate_128, key, keylen);
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_128, output, nblocks);
		output += (nblocks * HKDS_KECCAK_128_RATE);
		outlen -= (nblocks * HKDS_KECCAK_128_RATE);

		if (outlen != 0U)
		{
			hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_128, hash, 1U);
			utils_memory_copy(output, hash, outlen);
		}

		hkds_keccak_dispose(&ctx);
	}
}

void hkds_shake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(key != NULL);

	HKDS_SIMD_ALIGN uint8_t hash[HKDS_KECCAK_256_RATE] = { 0U };
	const size_t nblocks = outlen / HKDS_KECCAK_256_RATE;
	hkds_keccak_state ctx;

	if (output != NULL && key != NULL)
	{
		hkds_shake_initialize(&ctx, hkds_keccak_rate_256, key, keylen);
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_256, output, nblocks);
		output += (nblocks * HKDS_KECCAK_256_RATE);
		outlen -= (nblocks * HKDS_KECCAK_256_RATE);

		if (outlen != 0U)
		{
			hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_256, hash, 1U);
			utils_memory_copy(output, hash, outlen);
		}

		hkds_keccak_dispose(&ctx);
	}
}

void hkds_shake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(key != NULL);

	HKDS_SIMD_ALIGN uint8_t hash[HKDS_KECCAK_512_RATE] = { 0U };
	const size_t nblocks = outlen / HKDS_KECCAK_512_RATE;
	hkds_keccak_state ctx;

	if (output != NULL && key != NULL)
	{
		hkds_shake_initialize(&ctx, hkds_keccak_rate_512, key, keylen);
		hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_512, output, nblocks);
		output += (nblocks * HKDS_KECCAK_512_RATE);
		outlen -= (nblocks * HKDS_KECCAK_512_RATE);

		if (outlen != 0U)
		{
			hkds_shake_squeezeblocks(&ctx, hkds_keccak_rate_512, hash, 1U);
			utils_memory_copy(output, hash, outlen);
		}

		hkds_keccak_dispose(&ctx);
	}
}

void hkds_shake_initialize(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* key, size_t keylen)
{
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(key != NULL);

	hkds_keccak_initialize_state(ctx);
	hkds_keccak_absorb(ctx, rate, key, keylen, HKDS_KECCAK_SHAKE_DOMAIN_ID, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

void hkds_shake_squeezeblocks(hkds_keccak_state* ctx, hkds_keccak_rate rate, uint8_t* output, size_t nblocks)
{
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(output != NULL);

	hkds_keccak_squeezeblocks(ctx, output, nblocks, rate, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

/* KMAC */

void hkds_kmac128_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(message != NULL);
	HKDS_ASSERT(key != NULL);

	hkds_keccak_state ctx;

	hkds_kmac_initialize(&ctx, hkds_keccak_rate_128, key, keylen, custom, custlen);
	hkds_kmac_update(&ctx, hkds_keccak_rate_128, message, msglen);
	hkds_kmac_finalize(&ctx, hkds_keccak_rate_128, output, outlen);
}

void hkds_kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(message != NULL);
	HKDS_ASSERT(key != NULL);

	hkds_keccak_state ctx;

	hkds_kmac_initialize(&ctx, hkds_keccak_rate_256, key, keylen, custom, custlen);
	hkds_kmac_update(&ctx, hkds_keccak_rate_256, message, msglen);
	hkds_kmac_finalize(&ctx, hkds_keccak_rate_256, output, outlen);
}

void hkds_kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(message != NULL);
	HKDS_ASSERT(key != NULL);

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
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(key != NULL);

	HKDS_SIMD_ALIGN const uint8_t name[4U] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

	hkds_keccak_absorb_key_custom(ctx, rate, key, keylen, custom, custlen, name, sizeof(name), HKDS_KECCAK_PERMUTATION_ROUNDS);
}

void hkds_kmac_update(hkds_keccak_state* ctx, hkds_keccak_rate rate, const uint8_t* message, size_t msglen)
{
	HKDS_ASSERT(ctx != NULL);
	HKDS_ASSERT(message != NULL);

	hkds_keccak_update(ctx, rate, message, msglen, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

/* parallel SHAKE x4 */

#if defined(HKDS_SYSTEM_HAS_AVX2)

void hkds_keccakx4_absorb(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen, uint8_t domain)
{
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);

	if (inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL)
	{
		__m256i t;
		uint64_t v0;
		uint64_t v1;
		uint64_t v2;
		uint64_t v3;
		size_t pos;
		size_t i;

		pos = 0U;

		/* process full blocks */
		while (inplen >= (size_t)rate)
		{
			for (i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				v0 = *(const uint64_t*)(inp0 + pos);
				v1 = *(const uint64_t*)(inp1 + pos);
				v2 = *(const uint64_t*)(inp2 + pos);
				v3 = *(const uint64_t*)(inp3 + pos);

				t = _mm256_set_epi64x(v3, v2, v1, v0);
				state[i] = _mm256_xor_si256(state[i], t);

				pos += sizeof(uint64_t);
			}

			hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			inplen -= (size_t)rate;
		}

		i = 0U;

		/* process remaining input */
		while (inplen >= sizeof(uint64_t))
		{
			v0 = *(const uint64_t*)(inp0 + pos);
			v1 = *(const uint64_t*)(inp1 + pos);
			v2 = *(const uint64_t*)(inp2 + pos);
			v3 = *(const uint64_t*)(inp3 + pos);

			t = _mm256_set_epi64x(v3, v2, v1, v0);
			state[i] = _mm256_xor_si256(state[i], t);

			++i;
			pos += sizeof(uint64_t);
			inplen -= sizeof(uint64_t);
		}

		/* partial block */
		if (inplen != 0U)
		{
			v0 = 0U;
			v1 = 0U;
			v2 = 0U;
			v3 = 0U;

			/* copy remaining bytes into temporary variables */
			for (size_t j = 0U; j < inplen; ++j)
			{
				((uint8_t*)&v0)[j] = inp0[pos + j];
				((uint8_t*)&v1)[j] = inp1[pos + j];
				((uint8_t*)&v2)[j] = inp2[pos + j];
				((uint8_t*)&v3)[j] = inp3[pos + j];
			}

			t = _mm256_set_epi64x(v3, v2, v1, v0);
			state[i] = _mm256_xor_si256(state[i], t);
		}

		/* apply domain separation and padding */
		t = _mm256_set1_epi64x((int64_t)domain << (sizeof(uint64_t) * inplen));
		state[i] = _mm256_xor_si256(state[i], t);
		t = _mm256_set1_epi64x(1ULL << 63);
		state[((size_t)rate / sizeof(uint64_t)) - 1U] = _mm256_xor_si256(state[((size_t)rate / sizeof(uint64_t)) - 1U], t);
	}
}

void hkds_keccakx4_squeezeblocks(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t nblocks)
{
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);

	HKDS_ALIGN(32) uint64_t tmp[4U] = { 0 };

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL)
	{
		while (nblocks > 0U)
		{
			hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

			for (size_t i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				_mm256_store_si256((__m256i*)tmp, state[i]);

				utils_integer_le64to8(out0, tmp[0U]);
				utils_integer_le64to8(out1, tmp[1U]);
				utils_integer_le64to8(out2, tmp[2U]);
				utils_integer_le64to8(out3, tmp[3U]);

				out0 += sizeof(uint64_t);
				out1 += sizeof(uint64_t);
				out2 += sizeof(uint64_t);
				out3 += sizeof(uint64_t);
			}

			--nblocks;
		}
	}
}

#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)

#define _mm512_extract_epi64x(b, i) ( \
        _mm_extract_epi64(_mm512_extracti64x2_epi64(b, i / 2), i % 2))

void hkds_keccakx8_absorb(__m512i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen, uint8_t domain)
{
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);
	HKDS_ASSERT(inp4 != NULL);
	HKDS_ASSERT(inp5 != NULL);
	HKDS_ASSERT(inp6 != NULL);
	HKDS_ASSERT(inp7 != NULL);

	if (inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL &&
		inp4 != NULL && inp5 != NULL && inp6 != NULL && inp7 != NULL) 
	{
		__m512i t;
		uint64_t v0;
		uint64_t v1;
		uint64_t v2;
		uint64_t v3;
		uint64_t v4;
		uint64_t v5;
		uint64_t v6;
		uint64_t v7;
		size_t pos;
		size_t i;

		pos = 0U;

		/* process full blocks */
		while (inplen >= (size_t)rate)
		{
			for (i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				v0 = *(const uint64_t*)(inp0 + pos);
				v1 = *(const uint64_t*)(inp1 + pos);
				v2 = *(const uint64_t*)(inp2 + pos);
				v3 = *(const uint64_t*)(inp3 + pos);
				v4 = *(const uint64_t*)(inp4 + pos);
				v5 = *(const uint64_t*)(inp5 + pos);
				v6 = *(const uint64_t*)(inp6 + pos);
				v7 = *(const uint64_t*)(inp7 + pos);

				t = _mm512_set_epi64(v7, v6, v5, v4, v3, v2, v1, v0);
				state[i] = _mm512_xor_si512(state[i], t);

				pos += sizeof(uint64_t);
			}

			hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			inplen -= (size_t)rate;
		}

		i = 0U;

		/* process remaining input */
		while (inplen >= sizeof(uint64_t))
		{
			v0 = *(const uint64_t*)(inp0 + pos);
			v1 = *(const uint64_t*)(inp1 + pos);
			v2 = *(const uint64_t*)(inp2 + pos);
			v3 = *(const uint64_t*)(inp3 + pos);
			v4 = *(const uint64_t*)(inp4 + pos);
			v5 = *(const uint64_t*)(inp5 + pos);
			v6 = *(const uint64_t*)(inp6 + pos);
			v7 = *(const uint64_t*)(inp7 + pos);

			t = _mm512_set_epi64(v7, v6, v5, v4, v3, v2, v1, v0);
			state[i] = _mm512_xor_si512(state[i], t);

			i++;
			pos += sizeof(uint64_t);
			inplen -= sizeof(uint64_t);
		}

		/* handle the remaining partial block */
		if (inplen != 0U)
		{
			v0 = 0U;
			v1 = 0U;
			v2 = 0U;
			v3 = 0U;
			v4 = 0U;
			v5 = 0U;
			v6 = 0U;
			v7 = 0U;

			/* copy remaining bytes into temporary variables*/
			for (size_t j = 0U; j < inplen; ++j)
			{
				((uint8_t*)&v0)[j] = inp0[pos + j];
				((uint8_t*)&v1)[j] = inp1[pos + j];
				((uint8_t*)&v2)[j] = inp2[pos + j];
				((uint8_t*)&v3)[j] = inp3[pos + j];
				((uint8_t*)&v4)[j] = inp4[pos + j];
				((uint8_t*)&v5)[j] = inp5[pos + j];
				((uint8_t*)&v6)[j] = inp6[pos + j];
				((uint8_t*)&v7)[j] = inp7[pos + j];
			}

			t = _mm512_set_epi64(v7, v6, v5, v4, v3, v2, v1, v0);
			state[i] = _mm512_xor_si512(state[i], t);
		}

		/* apply domain separation and padding */
		t = _mm512_set1_epi64((int64_t)domain << (sizeof(uint64_t) * inplen));
		state[i] = _mm512_xor_si512(state[i], t);
		t = _mm512_set1_epi64(1ULL << 63);
		state[((size_t)rate / sizeof(uint64_t)) - 1U] = _mm512_xor_si512(state[((size_t)rate / sizeof(uint64_t)) - 1U], t);
	}
}

void hkds_keccakx8_squeezeblocks(__m512i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, uint8_t* out4,
	uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t nblocks)
{
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(out4 != NULL);
	HKDS_ASSERT(out5 != NULL);
	HKDS_ASSERT(out6 != NULL);
	HKDS_ASSERT(out7 != NULL);

	size_t i;

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL)
	{
		while (nblocks > 0U)
		{
			hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

			HKDS_ALIGN(64) uint64_t tmp[8U] = { 0U };

			for (i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				_mm512_store_si512((__m512i*)tmp, state[i]);

				utils_integer_le64to8(out0, tmp[0U]);
				utils_integer_le64to8(out1, tmp[1U]);
				utils_integer_le64to8(out2, tmp[2U]);
				utils_integer_le64to8(out3, tmp[3U]);
				utils_integer_le64to8(out4, tmp[4U]);
				utils_integer_le64to8(out5, tmp[5U]);
				utils_integer_le64to8(out6, tmp[6U]);
				utils_integer_le64to8(out7, tmp[7U]);

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
}

#endif

void hkds_shake_128x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(inplen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX2)

	size_t i;
	size_t nblocks = outlen / HKDS_KECCAK_128_RATE;
	HKDS_ALIGN(32) uint8_t t[4U][HKDS_KECCAK_128_RATE] = { 0U };
	HKDS_ALIGN(32) __m256i state[HKDS_KECCAK_STATE_SIZE] = { 0U };

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

	if (outlen != 0U)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_128, t[0U], t[1U], t[2U], t[3U], 1U);

		for (i = 0U; i < outlen; ++i)
		{
			out0[i] = t[0U][i];
			out1[i] = t[1U][i];
			out2[i] = t[2U][i];
			out3[i] = t[3U][i];
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
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(inplen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX2)

	size_t nblocks = outlen / HKDS_KECCAK_256_RATE;
	HKDS_ALIGN(32) uint8_t t[4U][HKDS_KECCAK_256_RATE] = { 0U };
	HKDS_ALIGN(32) __m256i state[HKDS_KECCAK_STATE_SIZE] = { 0U };

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

	if (outlen != 0U)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_256, t[0U], t[1U], t[2U], t[3U], 1U);

		for (size_t i = 0U; i < outlen; ++i)
		{
			out0[i] = t[0U][i];
			out1[i] = t[1U][i];
			out2[i] = t[2U][i];
			out3[i] = t[3U][i];
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
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(inplen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX2)

	size_t nblocks = outlen / HKDS_KECCAK_512_RATE;
	HKDS_ALIGN(32) uint8_t t[4U][HKDS_KECCAK_512_RATE] = { 0U };
	HKDS_ALIGN(32) __m256i state[HKDS_KECCAK_STATE_SIZE] = { 0U };

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

	if (outlen != 0U)
	{
		hkds_keccakx4_squeezeblocks(state, hkds_keccak_rate_512, t[0U], t[1U], t[2U], t[3U], 1U);

		for (size_t i = 0U; i < outlen; ++i)
		{
			out0[i] = t[0U][i];
			out1[i] = t[1U][i];
			out2[i] = t[2U][i];
			out3[i] = t[3U][i];
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
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);
	HKDS_ASSERT(inp4 != NULL);
	HKDS_ASSERT(inp5 != NULL);
	HKDS_ASSERT(inp6 != NULL);
	HKDS_ASSERT(inp7 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(out4 != NULL);
	HKDS_ASSERT(out5 != NULL);
	HKDS_ASSERT(out6 != NULL);
	HKDS_ASSERT(out7 != NULL);
	HKDS_ASSERT(inplen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX512)

	size_t nblocks = outlen / HKDS_KECCAK_128_RATE;
	HKDS_ALIGN(64) uint8_t t[8U][HKDS_KECCAK_128_RATE] = { 0U };
	HKDS_ALIGN(64) __m512i state[HKDS_KECCAK_STATE_SIZE] = { 0U };

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

	if (outlen != 0U)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_128, t[0U], t[1U], t[2U], t[3U], t[4U], t[5U], t[6U], t[7U], 1U);

		for (size_t i = 0U; i < outlen; ++i)
		{
			out0[i] = t[0U][i];
			out1[i] = t[1U][i];
			out2[i] = t[2U][i];
			out3[i] = t[3U][i];
			out4[i] = t[4U][i];
			out5[i] = t[5U][i];
			out6[i] = t[6U][i];
			out7[i] = t[7U][i];
		}
	}

#elif defined(HKDS_SYSTEM_HAS_AVX2)

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
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);
	HKDS_ASSERT(inp4 != NULL);
	HKDS_ASSERT(inp5 != NULL);
	HKDS_ASSERT(inp6 != NULL);
	HKDS_ASSERT(inp7 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(out4 != NULL);
	HKDS_ASSERT(out5 != NULL);
	HKDS_ASSERT(out6 != NULL);
	HKDS_ASSERT(out7 != NULL);
	HKDS_ASSERT(inplen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX512)

	size_t nblocks = outlen / HKDS_KECCAK_256_RATE;
	HKDS_ALIGN(64) uint8_t t[8U][HKDS_KECCAK_256_RATE] = { 0U };
	HKDS_ALIGN(64) __m512i state[HKDS_KECCAK_STATE_SIZE] = { 0U };

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

	if (outlen != 0U)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_256, t[0U], t[1U], t[2U], t[3U], t[4U], t[5U], t[6U], t[7U], 1);

		for (size_t i = 0U; i < outlen; ++i)
		{
			out0[i] = t[0U][i];
			out1[i] = t[1U][i];
			out2[i] = t[2U][i];
			out3[i] = t[3U][i];
			out4[i] = t[4U][i];
			out5[i] = t[5U][i];
			out6[i] = t[6U][i];
			out7[i] = t[7U][i];
		}
	}

#elif defined(HKDS_SYSTEM_HAS_AVX2)

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
	HKDS_ASSERT(inp0 != NULL);
	HKDS_ASSERT(inp1 != NULL);
	HKDS_ASSERT(inp2 != NULL);
	HKDS_ASSERT(inp3 != NULL);
	HKDS_ASSERT(inp4 != NULL);
	HKDS_ASSERT(inp5 != NULL);
	HKDS_ASSERT(inp6 != NULL);
	HKDS_ASSERT(inp7 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(out4 != NULL);
	HKDS_ASSERT(out5 != NULL);
	HKDS_ASSERT(out6 != NULL);
	HKDS_ASSERT(out7 != NULL);
	HKDS_ASSERT(inplen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX512)

	size_t nblocks = outlen / HKDS_KECCAK_512_RATE;
	HKDS_ALIGN(64) uint8_t t[8U][HKDS_KECCAK_512_RATE] = { 0U };
	HKDS_ALIGN(64) __m512i state[HKDS_KECCAK_STATE_SIZE] = { 0U };

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

	if (outlen != 0U)
	{
		hkds_keccakx8_squeezeblocks(state, hkds_keccak_rate_512, t[0U], t[1U], t[2U], t[3U], t[4U], t[5U], t[6U], t[7U], 1U);

		for (size_t i = 0U; i < outlen; ++i)
		{
			out0[i] = t[0U][i];
			out1[i] = t[1U][i];
			out2[i] = t[2U][i];
			out3[i] = t[3U][i];
			out4[i] = t[4U][i];
			out5[i] = t[5U][i];
			out6[i] = t[6U][i];
			out7[i] = t[7U][i];
		}
	}

#elif defined(HKDS_SYSTEM_HAS_AVX2)

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

#if defined(HKDS_SYSTEM_HAS_AVX2)

static void kmacx4_fast_absorb(__m256i state[HKDS_KECCAK_STATE_SIZE], const uint8_t* inp0, const uint8_t* inp1,
	const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	__m256i t;
	HKDS_ALIGN(32) uint64_t tmps[4U] = { 0U };
	size_t pos;

	pos = 0U;

	for (size_t i = 0U; i < inplen / sizeof(uint64_t); ++i)
	{
		tmps[0U] = utils_integer_le8to64(inp0 + pos);
		tmps[1U] = utils_integer_le8to64(inp1 + pos);
		tmps[2U] = utils_integer_le8to64(inp2 + pos);
		tmps[3U] = utils_integer_le8to64(inp3 + pos);

		t = _mm256_loadu_si256((const __m256i*)tmps);
		state[i] = _mm256_xor_si256(state[i], t);
		pos += 8U;
	}
}

static void kmacx4_customize(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* name, size_t nmelen)
{
	HKDS_ALIGN(32) uint8_t pad[4U][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	size_t oft;
	size_t i;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad[0U], (size_t)rate);
	oft += keccak_left_encode((pad[0U] + oft), nmelen * 8U);

	for (i = 0U; i < nmelen; ++i)
	{
		pad[0U][oft + i] = name[i];
	}

	oft += nmelen;
	oft += keccak_left_encode((pad[0U] + oft), cstlen * 8U);
	utils_memory_copy(pad[1U], pad[0U], oft);
	utils_memory_copy(pad[2U], pad[0U], oft);
	utils_memory_copy(pad[3U], pad[0U], oft);

	for (i = 0U; i < cstlen; ++i)
	{
		if (oft == rate)
		{
			kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);
			hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = cst0[i];
		pad[1U][oft] = cst1[i];
		pad[2U][oft] = cst2[i];
		pad[3U][oft] = cst3[i];
		++oft;
	}

	kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

	/* stage 2: key */

	utils_memory_clear(pad[0U], oft);
	utils_memory_clear(pad[1U], oft);
	utils_memory_clear(pad[2U], oft);
	utils_memory_clear(pad[3U], oft);

	oft = keccak_left_encode(pad[0U], (size_t)rate);
	oft += keccak_left_encode((pad[0U] + oft), keylen * 8U);
	utils_memory_copy(pad[1U], pad[0U], oft);
	utils_memory_copy(pad[2U], pad[0U], oft);
	utils_memory_copy(pad[3U], pad[0U], oft);

	for (i = 0U; i < keylen; ++i)
	{
		if (oft == rate)
		{
			kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);
			hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = key0[i];
		pad[1U][oft] = key1[i];
		pad[2U][oft] = key2[i];
		pad[3U][oft] = key3[i];
		++oft;
	}

	utils_memory_clear((pad[0U] + oft), (size_t)rate - oft);
	utils_memory_clear((pad[1U] + oft), (size_t)rate - oft);
	utils_memory_clear((pad[2U] + oft), (size_t)rate - oft);
	utils_memory_clear((pad[3U] + oft), (size_t)rate - oft);

	kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

static void kmacx4_finalize(__m256i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen)
{
	HKDS_ALIGN(32) uint8_t tmps[4U][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	HKDS_ALIGN(32) uint8_t buf[sizeof(size_t) + 1] = { 0U };
	HKDS_ALIGN(32) uint8_t pad[4U][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	const size_t BLKCNT = outlen / (size_t)rate;
	size_t bitlen;
	size_t i;
	size_t pos;

	pos = 0U;

	while (msglen >= (size_t)rate)
	{
		kmacx4_fast_absorb(state, (msg0 + pos), (msg1 + pos), (msg2 + pos), (msg3 + pos), (size_t)rate);
		hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos += (size_t)rate;
		msglen -= (size_t)rate;
	}

	if (msglen > 0U)
	{
		utils_memory_copy(pad[0U], (msg0 + pos), msglen);
		utils_memory_copy(pad[1U], (msg1 + pos), msglen);
		utils_memory_copy(pad[2U], (msg2 + pos), msglen);
		utils_memory_copy(pad[3U], (msg3 + pos), msglen);
	}

	pos = msglen;
	bitlen = keccak_right_encode(buf, outlen * 8U);

	if (pos + bitlen >= (size_t)rate)
	{
		kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);
		hkds_keccak_permute_p4x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos = 0U;
	}

	utils_memory_copy((pad[0U] + pos), buf, bitlen);
	pad[0U][pos + bitlen] = HKDS_KECCAK_KMAC_DOMAIN_ID;
	pad[0U][rate - 1U] |= 128U;
	utils_memory_copy((pad[1U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[2U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[3U] + pos), (pad[0U] + pos), (size_t)rate - pos);

	kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);

	if (outlen > (size_t)rate)
	{
		hkds_keccakx4_squeezeblocks(state, rate, out0, out1, out2, out3, BLKCNT);

		out0 += BLKCNT * (size_t)rate;
		out1 += BLKCNT * (size_t)rate;
		out2 += BLKCNT * (size_t)rate;
		out3 += BLKCNT * (size_t)rate;
		outlen -= BLKCNT * (size_t)rate;
	}

	if (outlen != 0U)
	{
		hkds_keccakx4_squeezeblocks(state, rate, tmps[0U], tmps[1U], tmps[2U], tmps[3U], 1U);

		for (i = 0U; i < outlen; ++i)
		{
			out0[i] = tmps[0U][i];
			out1[i] = tmps[1U][i];
			out2[i] = tmps[2U][i];
			out3[i] = tmps[3U][i];
		}
	}
}

#endif

void hkds_kmac_128x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen)
{
	HKDS_ASSERT(key0 != NULL);
	HKDS_ASSERT(key1 != NULL);
	HKDS_ASSERT(key2 != NULL);
	HKDS_ASSERT(key3 != NULL);
	HKDS_ASSERT(msg0 != NULL);
	HKDS_ASSERT(msg1 != NULL);
	HKDS_ASSERT(msg2 != NULL);
	HKDS_ASSERT(msg3 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(keylen != 0U);
	HKDS_ASSERT(msglen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX2)

	HKDS_ALIGN(32) __m256i state[HKDS_KECCAK_STATE_SIZE] = { 0U };
	const HKDS_ALIGN(32) uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

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
	HKDS_ASSERT(key0 != NULL);
	HKDS_ASSERT(key1 != NULL);
	HKDS_ASSERT(key2 != NULL);
	HKDS_ASSERT(key3 != NULL);
	HKDS_ASSERT(msg0 != NULL);
	HKDS_ASSERT(msg1 != NULL);
	HKDS_ASSERT(msg2 != NULL);
	HKDS_ASSERT(msg3 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(keylen != 0U);
	HKDS_ASSERT(msglen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX2)

	HKDS_ALIGN(32) __m256i state[HKDS_KECCAK_STATE_SIZE] = { 0U };
	const uint8_t HKDS_ALIGN(32) name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

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
	HKDS_ASSERT(key0 != NULL);
	HKDS_ASSERT(key1 != NULL);
	HKDS_ASSERT(key2 != NULL);
	HKDS_ASSERT(key3 != NULL);
	HKDS_ASSERT(msg0 != NULL);
	HKDS_ASSERT(msg1 != NULL);
	HKDS_ASSERT(msg2 != NULL);
	HKDS_ASSERT(msg3 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(keylen != 0U);
	HKDS_ASSERT(msglen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX2)

	HKDS_ALIGN(32) __m256i state[HKDS_KECCAK_STATE_SIZE] = { 0U };
	const HKDS_ALIGN(32) uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

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

#if defined(HKDS_SYSTEM_HAS_AVX512)

static void kmacx8_fast_absorb(__m512i state[HKDS_KECCAK_STATE_SIZE],
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7,
	size_t inplen)
{
	__m512i t;
	HKDS_ALIGN(64) uint64_t tmps[8U] = { 0U };
	size_t pos;

	pos = 0U;

	for (size_t i = 0U; i < inplen / sizeof(uint64_t); ++i)
	{
		tmps[0U] = utils_integer_le8to64((inp0 + pos));
		tmps[1U] = utils_integer_le8to64((inp1 + pos));
		tmps[2U] = utils_integer_le8to64((inp2 + pos));
		tmps[3U] = utils_integer_le8to64((inp3 + pos));
		tmps[4U] = utils_integer_le8to64((inp4 + pos));
		tmps[5U] = utils_integer_le8to64((inp5 + pos));
		tmps[6U] = utils_integer_le8to64((inp6 + pos));
		tmps[7U] = utils_integer_le8to64((inp7 + pos));

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
	HKDS_ALIGN(64) uint8_t pad[8U][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	size_t oft;
	size_t i;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad[0U], rate);
	oft += keccak_left_encode((pad[0U] + oft), nmelen * 8U);

	for (i = 0U; i < nmelen; ++i)
	{
		pad[0U][oft + i] = name[i];
	}

	oft += nmelen;
	oft += keccak_left_encode((pad[0U] + oft), cstlen * 8U);
	utils_memory_copy(pad[1U], pad[0U], oft);
	utils_memory_copy(pad[2U], pad[0U], oft);
	utils_memory_copy(pad[3U], pad[0U], oft);
	utils_memory_copy(pad[4U], pad[0U], oft);
	utils_memory_copy(pad[5U], pad[0U], oft);
	utils_memory_copy(pad[6U], pad[0U], oft);
	utils_memory_copy(pad[7U], pad[0U], oft);

	for (i = 0U; i < cstlen; ++i)
	{
		if (oft == rate)
		{
			kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], (size_t)rate);
			hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = cst0[i];
		pad[1U][oft] = cst1[i];
		pad[2U][oft] = cst2[i];
		pad[3U][oft] = cst3[i];
		pad[4U][oft] = cst4[i];
		pad[5U][oft] = cst5[i];
		pad[6U][oft] = cst6[i];
		pad[7U][oft] = cst7[i];
		++oft;
	}

	kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);

	/* stage 2: key */

	utils_memory_clear(pad[0U], oft);
	utils_memory_clear(pad[1U], oft);
	utils_memory_clear(pad[2U], oft);
	utils_memory_clear(pad[3U], oft);
	utils_memory_clear(pad[4U], oft);
	utils_memory_clear(pad[5U], oft);
	utils_memory_clear(pad[6U], oft);
	utils_memory_clear(pad[7U], oft);

	oft = keccak_left_encode(pad[0U], rate);
	oft += keccak_left_encode((pad[0U] + oft), keylen * 8);
	utils_memory_copy(pad[1U], pad[0U], oft);
	utils_memory_copy(pad[2U], pad[0U], oft);
	utils_memory_copy(pad[3U], pad[0U], oft);
	utils_memory_copy(pad[4U], pad[0U], oft);
	utils_memory_copy(pad[5U], pad[0U], oft);
	utils_memory_copy(pad[6U], pad[0U], oft);
	utils_memory_copy(pad[7U], pad[0U], oft);

	for (i = 0U; i < keylen; ++i)
	{
		if (oft == rate)
		{
			kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], rate);
			hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = key0[i];
		pad[1U][oft] = key1[i];
		pad[2U][oft] = key2[i];
		pad[3U][oft] = key3[i];
		pad[4U][oft] = key4[i];
		pad[5U][oft] = key5[i];
		pad[6U][oft] = key6[i];
		pad[7U][oft] = key7[i];
		++oft;
	}

	kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], oft + (sizeof(uint64_t) - oft % sizeof(uint64_t)));
	hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
}

static void kmacx8_finalize(__m512i state[HKDS_KECCAK_STATE_SIZE], hkds_keccak_rate rate,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen)
{
	HKDS_ALIGN(64) uint8_t tmps[8U][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	HKDS_ALIGN(64) uint8_t buf[sizeof(size_t) + 1] = { 0U };
	HKDS_ALIGN(64) uint8_t pad[8U][HKDS_KECCAK_STATE_BYTE_SIZE] = { 0U };
	const size_t BLKCNT = outlen / (size_t)rate;
	size_t bitlen;
	size_t i;
	size_t pos;

	pos = 0U;

	while (msglen >= (size_t)rate)
	{
		kmacx8_fast_absorb(state, (msg0 + pos), (msg1 + pos), (msg2 + pos), (msg3 + pos),
			(msg4 + pos), (msg5 + pos), (msg6 + pos), (msg7 + pos), (size_t)rate);

		hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos += (size_t)rate;
		msglen -= (size_t)rate;
	}

	if (msglen > 0U)
	{
		utils_memory_copy(pad[0U], (msg0 + pos), msglen);
		utils_memory_copy(pad[1U], (msg1 + pos), msglen);
		utils_memory_copy(pad[2U], (msg2 + pos), msglen);
		utils_memory_copy(pad[3U], (msg3 + pos), msglen);
		utils_memory_copy(pad[4U], (msg4 + pos), msglen);
		utils_memory_copy(pad[5U], (msg5 + pos), msglen);
		utils_memory_copy(pad[6U], (msg6 + pos), msglen);
		utils_memory_copy(pad[7U], (msg7 + pos), msglen);
	}

	pos = msglen;
	bitlen = keccak_right_encode(buf, outlen * 8U);

	if (pos + bitlen >= (size_t)rate)
	{
		kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], (size_t)rate);
		hkds_keccak_permute_p8x1600(state, HKDS_KECCAK_PERMUTATION_ROUNDS);
		pos = 0U;
	}

	utils_memory_copy((pad[0U] + pos), buf, bitlen);
	pad[0U][pos + bitlen] = HKDS_KECCAK_KMAC_DOMAIN_ID;
	pad[0U][rate - 1U] |= 128U;

	utils_memory_copy((pad[1U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[2U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[3U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[4U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[5U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[6U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	utils_memory_copy((pad[7U] + pos), (pad[0U] + pos), (size_t)rate - pos);

	kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], (size_t)rate);

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

	if (outlen != 0U)
	{
		hkds_keccakx8_squeezeblocks(state, rate, tmps[0U], tmps[1U], tmps[2U], tmps[3U], tmps[4U], tmps[5U], tmps[6U], tmps[7U], 1);

		for (i = 0U; i < outlen; ++i)
		{
			out0[i] = tmps[0U][i];
			out1[i] = tmps[1U][i];
			out2[i] = tmps[2U][i];
			out3[i] = tmps[3U][i];
			out4[i] = tmps[4U][i];
			out5[i] = tmps[5U][i];
			out6[i] = tmps[6U][i];
			out7[i] = tmps[7U][i];
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
	HKDS_ASSERT(key0 != NULL);
	HKDS_ASSERT(key1 != NULL);
	HKDS_ASSERT(key2 != NULL);
	HKDS_ASSERT(key3 != NULL);
	HKDS_ASSERT(key4 != NULL);
	HKDS_ASSERT(key5 != NULL);
	HKDS_ASSERT(key6 != NULL);
	HKDS_ASSERT(key7 != NULL);
	HKDS_ASSERT(msg0 != NULL);
	HKDS_ASSERT(msg1 != NULL);
	HKDS_ASSERT(msg2 != NULL);
	HKDS_ASSERT(msg3 != NULL);
	HKDS_ASSERT(msg4 != NULL);
	HKDS_ASSERT(msg5 != NULL);
	HKDS_ASSERT(msg6 != NULL);
	HKDS_ASSERT(msg7 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(out4 != NULL);
	HKDS_ASSERT(out5 != NULL);
	HKDS_ASSERT(out6 != NULL);
	HKDS_ASSERT(out7 != NULL);
	HKDS_ASSERT(keylen != 0U);
	HKDS_ASSERT(msglen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX512)

	HKDS_ALIGN(64) __m512i state[HKDS_KECCAK_STATE_SIZE] = { 0U };
	const HKDS_ALIGN(64) uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

	kmacx8_customize(state, hkds_keccak_rate_128, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
		cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
	kmacx8_finalize(state, hkds_keccak_rate_128, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
		out0, out1, out2, out3, out4, out5, out6, out7, outlen);

#elif defined(HKDS_SYSTEM_HAS_AVX2)

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
	HKDS_ASSERT(key0 != NULL);
	HKDS_ASSERT(key1 != NULL);
	HKDS_ASSERT(key2 != NULL);
	HKDS_ASSERT(key3 != NULL);
	HKDS_ASSERT(key4 != NULL);
	HKDS_ASSERT(key5 != NULL);
	HKDS_ASSERT(key6 != NULL);
	HKDS_ASSERT(key7 != NULL);
	HKDS_ASSERT(msg0 != NULL);
	HKDS_ASSERT(msg1 != NULL);
	HKDS_ASSERT(msg2 != NULL);
	HKDS_ASSERT(msg3 != NULL);
	HKDS_ASSERT(msg4 != NULL);
	HKDS_ASSERT(msg5 != NULL);
	HKDS_ASSERT(msg6 != NULL);
	HKDS_ASSERT(msg7 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(out4 != NULL);
	HKDS_ASSERT(out5 != NULL);
	HKDS_ASSERT(out6 != NULL);
	HKDS_ASSERT(out7 != NULL);
	HKDS_ASSERT(keylen != 0U);
	HKDS_ASSERT(msglen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX512)

	HKDS_ALIGN(64) __m512i state[HKDS_KECCAK_STATE_SIZE] = { 0U };
	const HKDS_ALIGN(64) uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

	kmacx8_customize(state, hkds_keccak_rate_256, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
		cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
	kmacx8_finalize(state, hkds_keccak_rate_256, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
		out0, out1, out2, out3, out4, out5, out6, out7, outlen);

#elif defined(HKDS_SYSTEM_HAS_AVX2)

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
	HKDS_ASSERT(key0 != NULL);
	HKDS_ASSERT(key1 != NULL);
	HKDS_ASSERT(key2 != NULL);
	HKDS_ASSERT(key3 != NULL);
	HKDS_ASSERT(key4 != NULL);
	HKDS_ASSERT(key5 != NULL);
	HKDS_ASSERT(key6 != NULL);
	HKDS_ASSERT(key7 != NULL);
	HKDS_ASSERT(msg0 != NULL);
	HKDS_ASSERT(msg1 != NULL);
	HKDS_ASSERT(msg2 != NULL);
	HKDS_ASSERT(msg3 != NULL);
	HKDS_ASSERT(msg4 != NULL);
	HKDS_ASSERT(msg5 != NULL);
	HKDS_ASSERT(msg6 != NULL);
	HKDS_ASSERT(msg7 != NULL);
	HKDS_ASSERT(out0 != NULL);
	HKDS_ASSERT(out1 != NULL);
	HKDS_ASSERT(out2 != NULL);
	HKDS_ASSERT(out3 != NULL);
	HKDS_ASSERT(out4 != NULL);
	HKDS_ASSERT(out5 != NULL);
	HKDS_ASSERT(out6 != NULL);
	HKDS_ASSERT(out7 != NULL);
	HKDS_ASSERT(keylen != 0U);
	HKDS_ASSERT(msglen != 0U);
	HKDS_ASSERT(outlen != 0U);

#if defined(HKDS_SYSTEM_HAS_AVX512)

	HKDS_ALIGN(64) __m512i state[HKDS_KECCAK_STATE_SIZE] = { 0U };
	const HKDS_ALIGN(64) uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

	kmacx8_customize(state, hkds_keccak_rate_512, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
		cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
	kmacx8_finalize(state, hkds_keccak_rate_512, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
		out0, out1, out2, out3, out4, out5, out6, out7, outlen);

#elif defined(HKDS_SYSTEM_HAS_AVX2)

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
