#include "utils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* bogus winbase.h error */
HKDS_SYSTEM_CONDITION_IGNORE(5105)

#if defined(HKDS_SYSTEM_OS_WINDOWS)
#	if defined(HKDS_SYSTEM_COMPILER_MSC)
#		pragma comment(lib, "Bcrypt.lib")
#	endif
#  include <Windows.h>
#  include <bcrypt.h>
#	if defined(HKDS_SYSTEM_ARCH_IX86)
#		include <intrin.h>
#		pragma intrinsic(__cpuid)
#	elif defined(HKDS_SYSTEM_ARCH_ARM)
#		include <processthreadsapi.h>
#	endif
#elif defined(HKDS_SYSTEM_OS_POSIX)
#	include <unistd.h>
#	include <sys/types.h>
#	if defined(HKDS_SYSTEM_OS_BSD) || defined(HKDS_SYSTEM_OS_APPLE)
#		include <errno.h>
#		include <stdlib.h>
#   	include <sys/param.h>
#   	include <sys/sysctl.h>
#	elif defined(HKDS_SYSTEM_OS_LINUX)
#       include <sys/auxv.h>
#		include <sys/random.h>
#	else
#		include <cpuid.h>
#   	include <limits.h>
#		include <x86intrin.h>
#		include <fcntl.h>
#		include <xsaveintrin.h>
#	endif
#	if defined(_AIX)
#		include <sys/systemcfg.h>
#	endif
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

static void utils_le32to8(uint8_t* output, uint32_t value)
{
	HKDS_ASSERT(output != NULL);

	output[0U] = (uint8_t)value & 0xFFU;
	output[1U] = (uint8_t)(value >> 8) & 0xFFU;
	output[2U] = (uint8_t)(value >> 16) & 0xFFU;
	output[3U] = (uint8_t)(value >> 24) & 0xFFU;
}
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

			if (pos < 0U)
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

#if defined(HKDS_SYSTEM_ARCH_ARM)
#	if !defined(HWCAP_ARMv7)
#		define HWCAP_ARMv7 (1 << 29)
#	endif
#	if !defined(HWCAP_ASIMD)
#		define HWCAP_ASIMD (1 << 1)
#	endif
#	if !defined(HWCAP_NEON)
#		define HWCAP_NEON (1 << 12)
#	endif
#	if !defined(HWCAP_CRC32)
#		define HWCAP_CRC32 (1 << 7)
#	endif
#	if !defined(HWCAP2_CRC32)
#		define HWCAP2_CRC32 (1 << 4)
#	endif
#	if !defined(HWCAP_PMULL)
#		define HWCAP_PMULL (1 << 4)
#	endif
#	if !defined(HWCAP2_PMULL)
#		define HWCAP2_PMULL (1 << 1)
#	endif
#	if !defined(HWCAP_AES)
#		define HWCAP_AES (1 << 3)
#	endif
#	if !defined(HWCAP2_AES)
#		define HWCAP2_AES (1 << 0)
#	endif
#	if !defined(HWCAP_SHA1)
#		define HWCAP_SHA1 (1 << 5)
#	endif
#	if !defined(HWCAP_SHA2)
#		define HWCAP_SHA2 (1 << 6)
#	endif
#	if !defined(HWCAP2_SHA1)
#		define HWCAP2_SHA1 (1 << 2)
#	endif
#	if !defined(HWCAP2_SHA2)
#		define HWCAP2_SHA2 (1 << 3)
#	endif
#	if !defined(HWCAP_SM3)
#		define HWCAP_SM3 (1 << 18)
#	endif
#	if !defined(HWCAP_SM4)
#		define HWCAP_SM4 (1 << 19)
#	endif

static bool utils_is_armv7()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_ARMv7) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_ARMv7) != 0 ||
		(getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__arm__)
	res = true;
#elif defined(_WIN32) && defined(_M_ARM64)
	res = true;
#endif

	return res;
}

static bool utils_has_neon()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_ASIMD) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_ASIMD) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_ASIMD) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv8())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_pmull()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_PMULL) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_PMULL) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_PMULL) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_PMULL) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	/* M1 processor */
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_aes()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_AES) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_AES) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_sha256()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA2) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA2) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA2) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA2) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool utils_has_sha512()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA512) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA512) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA512) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA512) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
}
#endif

	return res;
}

static bool utils_has_sha3()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA3) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA3) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA3) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA3) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#endif

	return res;
}

static void utils_arm_features(utils_cpu_features* features)
{
	features->aesni = utils_has_aes();
	features->armv7 = utils_is_armv7();
	features->neon = utils_has_neon();
	features->pcmul = utils_has_pmull();
	features->sha256 = utils_has_sha256();
	features->sha512 = utils_has_sha512();
	features->sha3 = utils_has_sha3();
}

#endif

#if defined(HKDS_SYSTEM_ARCH_IX86) && !defined(HKDS_SYSTEM_OS_BSD)

#	define CPUID_EBX_AVX2 0x00000020UL
#	define CPUID_EBX_AVX512F 0x00010000UL
#	define CPUID_EBX_ADX 0x00080000UL
#	define CPUID_ECX_PCLMUL 0x00000002UL
#	define CPUID_ECX_AESNI 0x02000000UL
#	define CPUID_ECX_XSAVE 0x04000000UL
#	define CPUID_ECX_OSXSAVE 0x08000000UL
#	define CPUID_ECX_AVX 0x10000000UL
#	define CPUID_ECX_RDRAND 0x40000000UL
#	define CPUID_EDX_RDTCSP 0x0000001BUL
#	define CPUID_EBX_SHA2 0x20000000UL
#	define XCR0_SSE 0x00000002UL
#	define XCR0_AVX 0x00000004UL
#	define XCR0_OPMASK 0x00000020UL
#	define XCR0_ZMM_HI256 0x00000040UL
#	define XCR0_HI16_ZMM 0x00000080UL

static void utils_cpu_info(uint32_t info[4U], const uint32_t infotype)
{
#if defined(HKDS_SYSTEM_COMPILER_MSC) || defined(HKDS_SYSTEM_COMPILER_INTEL)
	__cpuid(info, infotype);
#elif defined(HKDS_SYSTEM_COMPILER_GCC) || defined(HKDS_SYSTEM_COMPILER_CLANG)
	__get_cpuid(infotype, (uint32_t*)&info[0U], (uint32_t*)&info[1U], (uint32_t*)&info[2U], (uint32_t*)&info[3U]);
#endif
}

static uint32_t utils_read_bits(uint32_t value, int index, int length)
{
	uint32_t mask;
	uint32_t res;

	res = 0U;

	if (length > 0 && length < 31)
	{
		mask = ((1U << length) - 1U) << (uint32_t)index;
		res = (value & mask) >> (uint32_t)index;
	}

	return res;
}

static void utils_vendor_name(utils_cpu_features* features)
{
	HKDS_ASSERT(features != NULL);

	int32_t info[4U] = { 0U };

	utils_cpu_info(info, 0x00000000UL);
	utils_memory_clear(features->vendor, HKDS_CPUIDEX_VENDOR_SIZE);
	utils_le32to8((uint8_t*)&features->vendor[0U], (uint32_t)info[1U]);
    utils_le32to8((uint8_t*)&features->vendor[4U], (uint32_t)info[3U]);
    utils_le32to8((uint8_t*)&features->vendor[8U], (uint32_t)info[2U]);
}

static void utils_bus_info(utils_cpu_features* features)
{
	HKDS_ASSERT(features != NULL);

	int32_t info[4U] = { 0U };

	utils_cpu_info(info, 0x00000000UL);

	if (info[0U] >= 0x00000016UL)
	{
		utils_memory_clear(info, sizeof(info));
		utils_cpu_info(info, 0x00000016UL);
		features->freqbase = info[0U];
		features->freqmax = info[1U];
		features->freqref = info[2U];
	}
}

static void utils_cpu_cache(utils_cpu_features* features)
{
	HKDS_ASSERT(features != NULL);

	int32_t info[4U] = { 0U };

	utils_cpu_info(info, 0x80000006UL);

	features->l1cache = utils_read_bits(info[2], 0, 8);
	features->l1cacheline = utils_read_bits(info[2], 0, 11);
	features->l2associative = utils_read_bits(info[2], 12, 4);
	features->l2cache = utils_read_bits(info[2], 16, 16);
}

static uint32_t utils_cpu_count()
{
	uint32_t resu;

	resu = 1U;

#if defined(HKDS_SYSTEM_OS_WINDOWS)
	uint32_t resl;
	SYSTEM_INFO sysinfo;

	GetSystemInfo(&sysinfo);
	resl = (uint32_t)sysinfo.dwNumberOfProcessors;

	if (resl > 1U)
	{
		resu = resl;
	}
#else
    long resl;
    
	resl = sysconf(_SC_NPROCESSORS_CONF);

    if (resl > 1L)
    {
        resu = (uint32_t)resl;
    }
#endif

	return resu;
}

static void utils_cpu_topology(utils_cpu_features* features)
{
	int32_t info[4U] = { 0U };

	/* total cpu cores */
	features->cores = utils_cpu_count();

	/* hyperthreading and actual cpus */
	utils_cpu_info(info, 0x00000001UL);
	features->hyperthread = utils_read_bits(info[3U], 28, 1) != 0;
	features->cpus = (features->hyperthread == true && features->cores > 1) ? (features->cores / 2) : features->cores;

	/* cache line size */
	utils_cpu_info(info, 0x00000001UL);

	/* cpu features */
	features->pcmul = ((info[2U] & CPUID_ECX_PCLMUL) != 0x00000000UL);
	features->aesni = ((info[2U] & CPUID_ECX_AESNI) != 0x00000000UL);
	features->rdrand = ((info[2U] & CPUID_ECX_RDRAND) != 0x00000000UL);
	features->rdtcsp = ((info[3U] & CPUID_EDX_RDTCSP) != 0x00000000UL);

#if defined(HKDS_SYSTEM_HAS_AVX)
	bool havx;

	havx = (info[2U] & CPUID_ECX_AVX) != 0x00000000UL;

	if (havx == true)
	{
		uint32_t xcr0;

		xcr0 = 0U;

		if ((info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
			(CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
		{
			xcr0 = (uint32_t)_xgetbv(0);
		}

		if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX))
		{
			features->avx = true;
		}
	}
#endif

	if (features->cputype == hkds_cpuid_intel)
	{
		features->cacheline = utils_read_bits(info[1], 16, 8) * 8U;
	}
	else if (features->cputype == hkds_cpuid_amd)
	{
		utils_cpu_info(info, 0x80000005UL);
		features->cacheline = utils_read_bits(info[2], 24, 8);
	}

	if (features->avx == true)
	{
#if defined(HKDS_SYSTEM_HAS_AVX2)
		bool havx2;

		utils_memory_clear(info, sizeof(info));
		utils_cpu_info(info, 0x00000007UL);

#	if defined(HKDS_SYSTEM_COMPILER_GCC)
		__builtin_cpu_init();
		havx2 = __builtin_cpu_supports("avx2") != 0;
#	else
		havx2 = ((info[1] & CPUID_EBX_AVX2) != 0x00000000UL);
#	endif

		features->adx = ((info[1] & CPUID_EBX_ADX) != 0x00000000UL);
		features->avx2 = havx2 && ((uint32_t)_xgetbv(0) & 0x000000E6UL) != 0x00000000UL;
		features->sha256 = ((info[1] & CPUID_EBX_SHA2) != 0x00000000UL);
#endif

#if defined(HKDS_SYSTEM_HAS_AVX512)
		bool havx512;
#	if defined(HKDS_SYSTEM_COMPILER_GCC)
		havx512 = __builtin_cpu_supports("avx512f") != 0;
#	else
		havx512 = ((info[1] & CPUID_EBX_AVX512F) != 0x00000000UL);
#	endif
		if (havx512 == true)
		{
			uint32_t xcr2 = (uint32_t)_xgetbv(0);

			if ((xcr2 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) ==
				(XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
			{
				features->avx512f = true;
			}
		}
#endif
	}
}

static void utils_cpu_type(utils_cpu_features* features)
{
	char tmpn[UTILS_CPUIDEX_VENDOR_SIZE + 1U] = { 0U };

	utils_vendor_name(features);
	utils_memory_copy(tmpn, features->vendor, UTILS_CPUIDEX_VENDOR_SIZE);
	utils_string_to_lowercase(tmpn);

	if (utils_string_contains(tmpn, "intel") == true)
	{
		features->cputype = hkds_cpuid_intel;
	}
	else if (utils_string_contains(tmpn, "amd") == true)
	{
		features->cputype = hkds_cpuid_amd;
	}
	else if (utils_string_contains(tmpn, "centaur") == true)
	{
		features->cputype = hkds_cpuid_via;
	}
	else if (utils_string_contains(tmpn, "via") == true)
	{
		features->cputype = hkds_cpuid_via;
	}
	else if (utils_string_contains(tmpn, "hygon") == true)
	{
		features->cputype = hkds_cpuid_hygion;
	}
	else
	{
		features->cputype = hkds_cpuid_unknown;
	}
}

static void utils_serial_number(utils_cpu_features* features)
{
	int32_t info[4U] = { 0U };

	utils_cpu_info(info, 0x00000003UL);
	utils_memory_clear(features->serial, UTILS_CPUIDEX_SERIAL_SIZE);
	utils_memory_copy(&features->serial[0U], &info[1U], sizeof(uint32_t));
	utils_memory_copy(&features->serial[4U], &info[3U], sizeof(uint32_t));
	utils_memory_copy(&features->serial[8U], &info[2U], sizeof(uint32_t));
}

#endif

#if defined(HKDS_SYSTEM_OS_BSD)

static void utils_bsd_topology(utils_cpu_features* features)
{
	size_t plen;
	uint64_t pval;

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.physicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cpus = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.logicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cores = pval;
		features->hyperthread = (pval > features->cpus);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency", &pval, &plen, NULL, 0) == 0)
	{
		features->freqbase = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_max", &pval, &plen, NULL, 0) == 0)
	{
		features->freqmax = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_min", &pval, &plen, NULL, 0) == 0)
	{
		features->freqref = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l1dcachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l1cache = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l2cachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l2cache = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.adx", &pval, &plen, NULL, 0) == 0)
	{
		features->adx = (pval == 1);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.aes", &pval, &plen, NULL, 0) == 0)
	{
		features->aesni = (pval == 1);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx1_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx = (pval == 1);
	}


	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx2_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx2 = (pval == 1);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx512f", &pval, &plen, NULL, 0) == 0)
	{
		features->avx512f = (pval == 1);
	}

	features->pcmul = features->avx;

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	features->rdtcsp = features->avx;

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	char vend[1024U] = { 0U };
	plen = sizeof(vend);

	if (sysctlbyname("machdep.cpu.brand_string", vend, &plen, NULL, 0) >= 0)
	{
		utils_memory_copy(features->vendor, vend, UTILS_CPUIDEX_VENDOR_SIZE - 1);
		utils_string_to_lowercase(vend);

		if (utils_string_contains(vend, "intel") == true)
		{
			features->cputype = hkds_cpuid_intel;
		}
		else if (utils_string_contains(vend, "amd") == true)
		{
			features->cputype = hkds_cpuid_amd;
		}
		else
		{
			features->cputype = hkds_cpuid_unknown;
		}
	}
}

#elif defined(HKDS_SYSTEM_OS_POSIX)

static void utils_posix_topology(utils_cpu_features* features)
{
#	if defined(HKDS_SYSTEM_ARCH_IX86) && defined(HKDS_SYSTEM_COMPILER_GCC)

	utils_cpu_type(features);

	if (features->cputype == hkds_cpuid_intel || features->cputype == hkds_cpuid_amd)
	{
		utils_bus_info(features);
		utils_cpu_cache(features);
		utils_cpu_topology(features);
		utils_serial_number(features);
	}

#	else

	int32_t res;

	res = sysconf(_SC_NPROCESSORS_CONF);

	if (res > 0)
	{
		features->cpus = (uint32_t)res;
	}

	res = sysconf(_SC_NPROCESSORS_ONLN);

	if (res > 0)
	{
		features->cores = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_SIZE);

	if (res > 0)
	{
		features->l1cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_LINESIZE);

	if (res > 0)
	{
		features->l1cacheline = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_SIZE);

	if (res > 0)
	{
		features->l2cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_ASSOC);

	if (res > 0)
	{
		features->l2associative = (uint32_t)res;
	}


	res = sysconf(_SC_LEVEL2_CACHE_LINESIZE);

	if (res > 0)
	{
		features->cacheline = (uint32_t)res;
	}
#	endif
}

#elif defined(HKDS_SYSTEM_OS_WINDOWS)

static void utils_windows_topology(utils_cpu_features* features)
{
#	if defined(HKDS_SYSTEM_ARCH_IX86)
	utils_cpu_type(features);

	if (features->cputype == hkds_cpuid_intel || features->cputype == hkds_cpuid_amd)
	{
		utils_bus_info(features);
		utils_cpu_cache(features);
		utils_cpu_topology(features);
		utils_serial_number(features);
	}
#	else

	features->cpus = utils_cpu_count();
	features->cores = features->cpus;

#	endif
}

#endif

bool utils_cpu_features_set(utils_cpu_features* features)
{
    bool res;

    features->adx = false;
    features->aesni = false;
    features->pcmul = false;
	/* ARM features */
	features->armv7 = false;
	features->neon = false;
	features->sha256 = false;
	features->sha512 = false;
	features->sha3 = false;
	/* Intel features */
    features->avx = false;
    features->avx2 = false;
    features->avx512f = false;
    features->hyperthread = false;
    features->rdrand = false;
    features->rdtcsp = false;
	/* cpu topology */
    features->cacheline = 0U;
    features->cores = 0U;
    features->cpus = 1U;
    features->freqbase = 0U;
    features->freqmax = 0U;
    features->freqref = 0U;
    features->l1cache = 0U;
    features->l1cacheline = 0U;
    features->l2associative = 4U;
    features->l2cache = 0U;
    utils_memory_clear(features->serial, UTILS_CPUIDEX_SERIAL_SIZE);

#if defined(HKDS_SYSTEM_OS_POSIX)
#	if defined(HKDS_SYSTEM_OS_BSD)
	utils_bsd_topology(features);
    res = true;
#else
	utils_posix_topology(features);
	res = true;
#endif
#elif defined(HKDS_SYSTEM_OS_WINDOWS)
	utils_windows_topology(features);
	res = true;
#else
	res = false;
#endif

#if defined(HKDS_SYSTEM_ARCH_ARM)
	utils_arm_features(features);
#endif

    return res;
}

uint64_t utils_stopwatch_start()
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
				if (utils_memory_are_equal(source + i, token, tlen) == true)
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