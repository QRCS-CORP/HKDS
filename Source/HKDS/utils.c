#include "utils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(HKDS_SYSTEM_OS_WINDOWS)
#	if defined(HKDS_SYSTEM_COMPILER_MSC)
#		pragma comment(lib, "Bcrypt.lib")
#	endif
#  include <Windows.h>
#  include <bcrypt.h>
#elif defined(HKDS_SYSTEM_OS_LINUX)
#  include <sys/random.h>
#  include <errno.h>
#  include <unistd.h>
#elif defined(HKDS_SYSTEM_OS_BSD) || defined(HKDS_SYSTEM_OS_APPLE)
#  include <stdlib.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#  include <errno.h>
#endif

/*!
 * \def HKDS_CPUIDEX_SERIAL_SIZE
 * \brief The CPU serial number length (in bytes).
 */
#define HKDS_CPUIDEX_SERIAL_SIZE 12ULL

#if defined(HKDS_SYSTEM_OS_APPLE) && defined(HKDS_SYSTEM_COMPILER_GCC)
	/*!
	 * \def HKDS_CPUIDEX_VENDOR_SIZE
	 * \brief The CPU vendor name length for Apple systems using GCC.
	 */
	#define HKDS_CPUIDEX_VENDOR_SIZE 32
#else
	/*!
	 * \def HKDS_CPUIDEX_VENDOR_SIZE
	 * \brief The CPU vendor name length.
	 */
	#define HKDS_CPUIDEX_VENDOR_SIZE 12ULL
#endif

void utils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	HKDS_ASSERT(hexstr != NULL);
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(length != 0U);

	uint8_t idx0;
	uint8_t idx1;

	const uint8_t hashmap[] =
	{
		0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
		0x08U, 0x09U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
		0x00U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x00U,
		0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
	};

	utils_memory_clear(output, length);

	for (size_t pos = 0U; pos < (length * 2U); pos += 2U)
	{
		idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1U] & 0x1FU) ^ 0x10U;
		output[pos / 2U] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

void utils_print_line(const char* input)
{
	HKDS_ASSERT(input != NULL);

	if (input != NULL)
	{
		utils_print_safe(input);
	}

	utils_print_safe("\n");
}

void utils_print_safe(const char* input)
{
	HKDS_ASSERT(input != NULL);

	if (input != NULL && utils_string_size(input) > 0U)
	{
#if defined(HKDS_SYSTEM_OS_WINDOWS)
		printf_s("%s", input);
#else
		printf("%s", input);
#endif
	}
}

bool utils_seed_generate(uint8_t* output, size_t length)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(length != 0U);

	bool res;

	res = false;

	if (output != NULL && length != 0U)
	{
		res = true;
#if defined(HKDS_SYSTEM_OS_WINDOWS)

		ULONG ulen = (ULONG)length;

		if (BCryptGenRandom(NULL, output, ulen, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		{
			res = false;
		}

#elif defined(HKDS_SYSTEM_OS_LINUX)

		ssize_t pos;
		size_t  rmd;
		uint8_t* ptr;

		rmd = length;
		ptr = output;

		while (rmd > 0U)
		{
			pos = getrandom(ptr, rmd, 0U);

			if (pos < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}

				res = false;
				break;
			}

			ptr += (size_t)pos;
			rmd -= (size_t)pos;
		}

#elif defined(HKDS_SYSTEM_OS_BSD) || defined(HKDS_SYSTEM_OS_APPLE)

		arc4random_buf(output, length);

#else

		int fd;

		/* fallback: read from /dev/urandom */

		do
		{
			fd = open("/dev/urandom", O_RDONLY);
		} while ((fd < 0) && (errno == EINTR));

		if (fd < 0)
		{
			res = false;
		}
		else
		{
			ssize_t pos;
			size_t rmd;
			uint8_t* ptr;

			rmd = length;
			ptr = output;

			while (rmd > 0U)
			{
				pos = read(fd, ptr, rmd);

				if (pos < 0)
				{
					if (errno == EINTR)
					{
						continue;
					}

					res = false;
					break;
				}
				else if (pos == 0)
				{
					/* zero-length read—treat as failure */
					res = false;
					break;
				}

				ptr += (size_t)pos;
				rmd -= (size_t)pos;
			}

			(void)close(fd);
		}

#endif
	}

	if (!res)
	{
		utils_memory_clear(output, length);
	}

	return res;
}

uint64_t utils_stopwatch_start(void)
{
	uint64_t start;

	start = (uint64_t)clock();

	return start;
}

uint64_t utils_stopwatch_elapsed(uint64_t start)
{
	uint64_t diff;
	uint64_t msec;

	msec = clock();
	diff = msec - start;
	msec = (diff * 1000U) / CLOCKS_PER_SEC;

	return msec;
}

int64_t utils_find_string(const char* source, const char* token)
{
	HKDS_ASSERT(source != NULL);
	HKDS_ASSERT(token != NULL);

	int64_t pos;

	pos = UTILS_TOKEN_NOT_FOUND;

	if (source != NULL && token != NULL)
	{
		size_t slen;
		size_t tlen;

		slen = utils_string_size(source);
		tlen = utils_string_size(token);

		for (size_t i = 0U; i < slen; ++i)
		{
			if (source[i] == token[0U])
			{
				/* safe cast: interpreting ASCII text as byte array for equality check */ 
				if (utils_memory_are_equal((const uint8_t*)source + i, (const uint8_t*)token, tlen) == true)
				{
					pos = i;
					break;
				}
			}
		}
	}

	return pos;
}

bool utils_string_contains(const char* source, const char* token)
{
	HKDS_ASSERT(source != NULL);
	HKDS_ASSERT(token != NULL);

	bool res;

	res = false;

	if (source != NULL && token != NULL)
	{
		res = (utils_find_string(source, token) >= 0);
	}

	return res;
}

size_t utils_string_size(const char* source)
{
	HKDS_ASSERT(source != NULL);

	size_t res;

	res = 0U;

	if (source != NULL)
	{
#if defined(HKDS_SYSTEM_OS_WINDOWS)
		res = strnlen_s(source, UTILS_STRING_MAX_LEN);
#else
		res = strlen(source);
#endif
	}

	return res;
}

void utils_string_to_lowercase(char* source)
{
	HKDS_ASSERT(source != NULL);

	if (source != NULL)
	{
#if defined(HKDS_SYSTEM_OS_WINDOWS)
		size_t slen;

		slen = utils_string_size(source) + 1U;
		_strlwr_s(source, slen);
#else
		for(size_t i = 0U; i < utils_string_size(source); ++i)
		{
			source[i] = tolower(source[i]);
		}
#endif
	}
}


#if defined(HKDS_SYSTEM_HAS_AVX)
static void utils_clear128(void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX2)
static void utils_clear256(void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_setzero_si256());
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
static void utils_clear512(void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_setzero_si512());
}
#endif

void utils_memory_clear(void* output, size_t length)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(length != 0U);

	size_t pctr;

	if (output != NULL && length != 0U)
	{
		pctr = 0U;

#if defined(HKDS_SYSTEM_AVX_INTRINSICS)
#	if defined(HKDS_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(HKDS_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#	if defined(HKDS_SYSTEM_HAS_AVX512)
				utils_clear512(((uint8_t*)output + pctr));
#	elif defined(HKDS_SYSTEM_HAS_AVX2)
				utils_clear256(((uint8_t*)output + pctr));
#	elif defined(HKDS_SYSTEM_HAS_AVX)
				utils_clear128(((uint8_t*)output + pctr));
#	endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32U)
		{
			utils_clear256(((uint8_t*)output + pctr));
			pctr += 32U;
		}
		else if (length - pctr >= 16U)
		{
			utils_clear128(((uint8_t*)output + pctr));
			pctr += 16U;
		}
#elif defined(HKDS_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16U)
		{
			utils_clear128(((uint8_t*)output + pctr));
			pctr += 16U;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = 0x00U;
			}
		}
	}
}

#if defined(HKDS_SYSTEM_HAS_AVX)
static bool utils_equal128(const uint8_t* a, const uint8_t* b)
{
	__m128i wa;
	__m128i wb;
	__m128i wc;
	uint64_t ra[sizeof(__m128i) / sizeof(uint64_t)] = { 0U };

	wa = _mm_loadu_si128((const __m128i*)a);
	wb = _mm_loadu_si128((const __m128i*)b);
	wc = _mm_cmpeq_epi64(wa, wb);
	_mm_storeu_si128((__m128i*)ra, wc);

	return ((~ra[0U] + ~ra[1U]) == 0U);
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX2)
static bool utils_equal256(const uint8_t* a, const uint8_t* b)
{
	__m256i wa;
	__m256i wb;
	__m256i wc;
	uint64_t ra[sizeof(__m256i) / sizeof(uint64_t)] = { 0U };

	wa = _mm256_loadu_si256((const __m256i*)a);
	wb = _mm256_loadu_si256((const __m256i*)b);
	wc = _mm256_cmpeq_epi64(wa, wb);
	_mm256_storeu_si256((__m256i*)ra, wc);

	return ((~ra[0U] + ~ra[1U] + ~ra[2U] + ~ra[3U]) == 0U);
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
static bool utils_equal512(const uint8_t* a, const uint8_t* b)
{
	__m512i va;
	__m512i vb;
	__mmask8 eq64;

    va = _mm512_loadu_si512(a);
    vb = _mm512_loadu_si512(b);
    eq64 = _mm512_cmpeq_epi64_mask(va, vb);

    return (eq64 == 0xFFU);
}
#endif

void utils_memory_aligned_free(void* block)
{
	HKDS_ASSERT(block != NULL);

	if (block != NULL)
	{
#if defined(HKDS_SYSTEM_AVX_INTRINSICS) && defined(HKDS_SYSTEM_OS_WINDOWS)
		_aligned_free(block);
#	else
		free(block);
#	endif
	}
}

void* utils_memory_aligned_alloc(int32_t align, size_t length)
{
	HKDS_ASSERT(align != 0);
	HKDS_ASSERT(length != 0U);

	(void)align;
	void* ret;

	ret = NULL;

	if (length != 0U)
	{
#if defined(HKDS_SYSTEM_AVX_INTRINSICS) && defined(HKDS_SYSTEM_OS_WINDOWS)
		ret = _aligned_malloc(length, align);
#elif defined(HKDS_SYSTEM_OS_POSIX)
		int32_t res;

		res = posix_memalign(&ret, align, length);

		if (res != 0)
		{
			ret = NULL;
		}
#else
		ret = (void*)malloc(length);
#endif
	}

	return ret;
}

bool utils_memory_are_equal(const uint8_t* a, const uint8_t* b, size_t length)
{
	HKDS_ASSERT(a != NULL);
	HKDS_ASSERT(b != NULL);
	HKDS_ASSERT(length > 0U);

	size_t pctr;
	int32_t mctr;

	mctr = 0;
	pctr = 0U;

	if (a != NULL && b != NULL && length != 0U)
	{
#if defined(HKDS_SYSTEM_AVX_INTRINSICS)
#	if defined(HKDS_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(HKDS_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(HKDS_SYSTEM_HAS_AVX512)
				mctr |= ((int32_t)utils_equal512(a + pctr, b + pctr) - 1U);
#elif defined(HKDS_SYSTEM_HAS_AVX2)
				mctr |= ((int32_t)utils_equal256(a + pctr, b + pctr) - 1U);
#elif defined(HKDS_SYSTEM_HAS_AVX)
				mctr |= ((int32_t)utils_equal128(a + pctr, b + pctr) - 1U);
#endif
				pctr += SMDBLK;
			}
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				mctr |= (a[i] ^ b[i]);
			}
		}
	}

	return (mctr == 0);
}

bool utils_memory_are_equal_128(const uint8_t* a, const uint8_t* b)
{
#if defined(HKDS_SYSTEM_HAS_AVX)

	return utils_equal128(a, b);

#else

	uint8_t mctr;

	mctr = 0;

	for (size_t i = 0U; i < 16U; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0U);

#endif
}

bool utils_memory_are_equal_256(const uint8_t* a, const uint8_t* b)
{
#if defined(HKDS_SYSTEM_HAS_AVX2)

	return utils_equal256(a, b);

#elif defined(HKDS_SYSTEM_HAS_AVX)

	return (utils_equal128(a, b) && 
		utils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)));

#else

	uint8_t mctr;

	mctr = 0;

	for (size_t i = 0U; i < 32U; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0U);

#endif
}

bool utils_memory_are_equal_512(const uint8_t* a, const uint8_t* b)
{
#if defined(HKDS_SYSTEM_HAS_AVX512)

	return utils_equal512(a, b);

#elif defined(HKDS_SYSTEM_HAS_AVX2)

	return utils_equal256(a, b) && 
		utils_equal256(a + sizeof(__m256i), b + sizeof(__m256i));

#elif defined(HKDS_SYSTEM_HAS_AVX)

	return (utils_equal128(a, b) && 
		utils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)) &&
		utils_equal128(a + (2 * sizeof(__m128i)), b + (2 * sizeof(__m128i))) &&
		utils_equal128(a + (3 * sizeof(__m128i)), b + (3 * sizeof(__m128i))));

#else

	uint8_t mctr;

	mctr = 0;

	for (size_t i = 0U; i < 64U; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0U);

#endif
}

#if defined(HKDS_SYSTEM_HAS_AVX)
static void utils_copy128(const void* input, void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_loadu_si128((const __m128i*)input));
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX2)
static void utils_copy256(const void* input, void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_loadu_si256((const __m256i*)input));
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
static void utils_copy512(const void* input, void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_loadu_si512((const __m512i*)input));
}
#endif

void utils_memory_copy(void* output, const void* input, size_t length)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(input != NULL);

	size_t pctr;

	if (output != NULL && input != NULL && length != 0U)
	{
		pctr = 0U;

#if defined(HKDS_SYSTEM_AVX_INTRINSICS)
#	if defined(HKDS_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(HKDS_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(HKDS_SYSTEM_HAS_AVX512)
				utils_copy512((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(HKDS_SYSTEM_HAS_AVX2)
				utils_copy256((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(HKDS_SYSTEM_HAS_AVX)
				utils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32U)
		{
			utils_copy256((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 32U;
		}
		else if (length - pctr >= 16U)
		{
			utils_copy128((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16;
		}
#elif defined(HKDS_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16U)
		{
			utils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16U;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = ((const uint8_t*)input)[i];
			}
		}
	}
}

#if defined(HKDS_SYSTEM_HAS_AVX)
static void utils_xor128(const uint8_t* input, uint8_t* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((const __m128i*)output)));
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX2)
static void utils_xor256(const uint8_t* input, uint8_t* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)input), _mm256_loadu_si256((const __m256i*)output)));
}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
static void utils_xor512(const uint8_t* input, uint8_t* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)input), _mm512_loadu_si512((__m512i*)output)));
}
#endif

void utils_memory_xor(uint8_t* output, const uint8_t* input, size_t length)
{
	HKDS_ASSERT(output != NULL);
	HKDS_ASSERT(input != NULL);
	HKDS_ASSERT(length != 0U);

	size_t pctr;

	pctr = 0U;

#if defined(HKDS_SYSTEM_AVX_INTRINSICS)
#	if defined(HKDS_SYSTEM_HAS_AVX512)
	const size_t SMDBLK = 64U;
#	elif defined(HKDS_SYSTEM_HAS_AVX2)
	const size_t SMDBLK = 32U;
#	else
	const size_t SMDBLK = 16U;
#	endif

	if (output != NULL && input != NULL && length >= SMDBLK)
	{
		const size_t ALNLEN = length - (length % SMDBLK);

		while (pctr != ALNLEN)
		{
#if defined(HKDS_SYSTEM_HAS_AVX512)
			utils_xor512((input + pctr), output + pctr);
#elif defined(HKDS_SYSTEM_HAS_AVX2)
			utils_xor256((input + pctr), output + pctr);
#elif defined(HKDS_SYSTEM_HAS_AVX)
			utils_xor128((input + pctr), output + pctr);
#endif
			pctr += SMDBLK;
		}
	}
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
	if (length - pctr >= 32U)
	{
		utils_xor256((input + pctr), output + pctr);
		pctr += 32U;
	}
	else if (length - pctr >= 16U)
	{
		utils_xor128((input + pctr), output + pctr);
		pctr += 16U;
	}
#elif defined(HKDS_SYSTEM_HAS_AVX2)
	if (length - pctr >= 16U)
	{
		utils_xor128((input + pctr), output + pctr);
		pctr += 16U;
	}
#endif

	if (pctr != length)
	{
		for (size_t i = pctr; i < length; ++i)
		{
			output[i] ^= input[i];
		}
	}
}

#if defined(HKDS_SYSTEM_HAS_AVX512)
static void utils_xorv512(const uint8_t value, uint8_t* output)
{
	__m512i v = _mm512_set1_epi8(value);
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)&v), _mm512_loadu_si512((__m512i*)output)));
}
#elif defined(HKDS_SYSTEM_HAS_AVX2)
static void utils_xorv256(const uint8_t value, uint8_t* output)
{
	__m256i v = _mm256_set1_epi8(value);
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*) & v), _mm256_loadu_si256((const __m256i*)output)));
}
#elif defined(HKDS_SYSTEM_HAS_AVX)
static void utils_xorv128(const uint8_t value, uint8_t* output)
{
	__m128i v = _mm_set1_epi8(value);
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*) & v), _mm_loadu_si128((const __m128i*)output)));
}
#endif

uint32_t utils_integer_be8to32(const uint8_t* input)
{
	return (uint32_t)(input[3U]) |
		(((uint32_t)(input[2U])) << 8) |
		(((uint32_t)(input[1U])) << 16) |
		(((uint32_t)(input[0U])) << 24);
}

void utils_integer_be32to8(uint8_t* output, uint32_t value)
{
	output[3U] = (uint8_t)value & 0xFFU;
	output[2U] = (uint8_t)(value >> 8) & 0xFFU;
	output[1U] = (uint8_t)(value >> 16) & 0xFFU;
	output[0U] = (uint8_t)(value >> 24) & 0xFFU;
}

uint64_t utils_integer_le8to64(const uint8_t* input)
{
	return ((uint64_t)input[0U]) |
		((uint64_t)input[1U] << 8) |
		((uint64_t)input[2U] << 16) |
		((uint64_t)input[3U] << 24) |
		((uint64_t)input[4U] << 32) |
		((uint64_t)input[5U] << 40) |
		((uint64_t)input[6U] << 48) |
		((uint64_t)input[7U] << 56);
}

void utils_integer_le64to8(uint8_t* output, uint64_t value)
{
	output[0U] = (uint8_t)value & 0xFFU;
	output[1U] = (uint8_t)(value >> 8) & 0xFFU;
	output[2U] = (uint8_t)(value >> 16) & 0xFFU;
	output[3U] = (uint8_t)(value >> 24) & 0xFFU;
	output[4U] = (uint8_t)(value >> 32) & 0xFFU;
	output[5U] = (uint8_t)(value >> 40) & 0xFFU;
	output[6U] = (uint8_t)(value >> 48) & 0xFFU;
	output[7U] = (uint8_t)(value >> 56) & 0xFFU;
}

void utils_integer_be8increment(uint8_t* output, size_t otplen)
{
	size_t i = otplen;

	if (otplen > 0U)
	{
		do
		{
			--i;
			++output[i];
		} 
		while (i != 0U && output[i] == 0U);
	}
}

uint64_t utils_integer_rotl64(uint64_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint64_t) * 8U) - shift));
}

int32_t utils_integer_verify(const uint8_t* a, const uint8_t* b, size_t length)
{
	uint8_t d;

	d = 0U;

	for (size_t i = 0U; i < length; ++i)
	{
		d |= (a[i] ^ b[i]);
	}

	return d;
}
