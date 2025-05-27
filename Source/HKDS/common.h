/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef HKDS_COMMON_H
#define HKDS_COMMON_H

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#if defined(__cplusplus)
#   define HKDS_CPLUSPLUS_ENABLED_START extern "C" {
#   define HKDS_CPLUSPLUS_ENABLED_END }
#else
#   define HKDS_CPLUSPLUS_ENABLED_START
#   define HKDS_CPLUSPLUS_ENABLED_END
#endif

HKDS_CPLUSPLUS_ENABLED_START

/*!
 * \file common.h
 * \brief Contains common definitions for the HKDS library.
 *
 * \details
 * This file provides common macros, type definitions, compiler/OS/architecture detection,
 * API export macros, alignment macros, secure memory allocation definitions, and other utility macros.
 * These definitions are used throughout the HKDS library to ensure portability and performance.
 */

/*==============================================================================
    Compiler Identification Macros
==============================================================================*/

#if defined(_MSC_VER)
  /*!
   * \def HKDS_SYSTEM_COMPILER_MSC
   * \brief Defined when the Microsoft Visual C++ compiler is detected.
   */
#	define HKDS_SYSTEM_COMPILER_MSC
#endif

#if defined(__MINGW32__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_MINGW
   * \brief Defined when using the MinGW compiler.
   */
#	define HKDS_SYSTEM_COMPILER_MINGW
  /*!
   * \def HKDS_SYSTEM_COMPILER_GCC
   * \brief Also defined for MinGW as it uses GCC.
   */
#	define HKDS_SYSTEM_COMPILER_GCC
#endif

#if defined(__CC_ARM)
  /*!
   * \def HKDS_SYSTEM_COMPILER_ARM
   * \brief Defined when using the ARM Compiler.
   */
#	define HKDS_SYSTEM_COMPILER_ARM
#endif

#if defined(__BORLANDC__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_BORLAND
   * \brief Defined when using the Borland C compiler.
   */
#	define HKDS_SYSTEM_COMPILER_BORLAND
#endif

#if defined(__GNUC__) && !defined(__MINGW32__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_GCC
   * \brief Defined when the GNU Compiler Collection (GCC) is detected.
   */
#	define HKDS_SYSTEM_COMPILER_GCC
#endif

#if defined(__clang__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_CLANG
   * \brief Defined when the Clang compiler is detected.
   */
#	define HKDS_SYSTEM_COMPILER_CLANG
#endif

#if defined(__IBMC__) || defined(__IBMCPP__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_IBM
   * \brief Defined when using the IBM compiler.
   */
#	define HKDS_SYSTEM_COMPILER_IBM
#endif

#if defined(__INTEL_COMPILER) || defined(__ICL)
  /*!
   * \def HKDS_SYSTEM_COMPILER_INTEL
   * \brief Defined when using the Intel compiler.
   */
#	define HKDS_SYSTEM_COMPILER_INTEL
#endif

#if defined(__MWERKS__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_MWERKS
   * \brief Defined when using the Metrowerks compiler.
   */
#	define HKDS_SYSTEM_COMPILER_MWERKS
#endif

#if defined(__OPEN64__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_OPEN64
   * \brief Defined when using the Open64 compiler.
   */
#	define HKDS_SYSTEM_COMPILER_OPEN64
#endif

#if defined(__SUNPRO_C)
  /*!
   * \def HKDS_SYSTEM_COMPILER_SUNPRO
   * \brief Defined when using the SunPro C compiler.
   */
#	define HKDS_SYSTEM_COMPILER_SUNPRO
#endif

#if defined(__TURBOC__)
  /*!
   * \def HKDS_SYSTEM_COMPILER_TURBO
   * \brief Defined when using the Turbo C compiler.
   */
#	define HKDS_SYSTEM_COMPILER_TURBO
#endif

/*==============================================================================
    Operating System Identification Macros
==============================================================================*/

#if defined(_WIN64) || defined(_WIN32) || defined(__WIN64__) || defined(__WIN32__)
  /*!
   * \def HKDS_SYSTEM_OS_WINDOWS
   * \brief Defined when the target operating system is Windows.
   */
#	if !defined(HKDS_SYSTEM_OS_WINDOWS)
#		define HKDS_SYSTEM_OS_WINDOWS
#	endif
#   if defined(_WIN64)
    /*!
     * \def HKDS_SYSTEM_ISWIN64
     * \brief Defined when building for 64-bit Windows.
     */
#		define HKDS_SYSTEM_ISWIN64
#   elif defined(_WIN32)
    /*!
     * \def HKDS_SYSTEM_ISWIN32
     * \brief Defined when building for 32-bit Windows.
     */
#		define HKDS_SYSTEM_ISWIN32
#   endif
#endif

#if defined(__ANDROID__)
  /*!
   * \def HKDS_SYSTEM_OS_ANDROID
   * \brief Defined when the target operating system is Android.
   */
#	define HKDS_SYSTEM_OS_ANDROID
#endif

#if defined(__APPLE__) || defined(__MACH__)
#   include "TargetConditionals.h"
  /*!
   * \def HKDS_SYSTEM_OS_APPLE
   * \brief Defined when the target operating system is Apple (macOS or iOS).
   */
#	define HKDS_SYSTEM_OS_APPLE
  /*!
   * \def HKDS_SYSTEM_OS_BSD
   * \brief Also defined for BSD-based operating systems (macOS is BSD-based).
   */
#	define HKDS_SYSTEM_OS_BSD
#   if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
    /*!
     * \def HKDS_SYSTEM_ISIPHONESIM
     * \brief Defined when building for the iPhone Simulator.
     */
#		define HKDS_SYSTEM_ISIPHONESIM
#   elif TARGET_OS_IPHONE
    /*!
     * \def HKDS_SYSTEM_ISIPHONE
     * \brief Defined when building for iPhone.
     */
#		define HKDS_SYSTEM_ISIPHONE
#   else
    /*!
     * \def HKDS_SYSTEM_ISOSX
     * \brief Defined when building for macOS.
     */
#		define HKDS_SYSTEM_ISOSX
#   endif
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) || defined(__DragonFly__) || defined(HKDS_SYSTEM_ISOSX)
  /*!
   * \def HKDS_SYSTEM_OS_BSD
   * \brief Defined when the target operating system is a BSD variant.
   */
#	define HKDS_SYSTEM_OS_BSD
#endif

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
  /*!
   * \def HKDS_SYSTEM_OS_LINUX
   * \brief Defined when the target operating system is Linux.
   */
#	define HKDS_SYSTEM_OS_LINUX
    typedef int32_t errno_t;
#endif

#if defined(__unix) || defined(__unix__)
  /*!
   * \def HKDS_SYSTEM_OS_UNIX
   * \brief Defined when the target operating system is Unix.
   */
#	define HKDS_SYSTEM_OS_UNIX
#   if defined(__hpux) || defined(hpux)
    /*!
     * \def HKDS_SYSTEM_OS_HPUX
     * \brief Defined when the target operating system is HP-UX.
     */
#		define HKDS_SYSTEM_OS_HPUX
#   endif
#   if defined(__sun__) || defined(__sun) || defined(sun)
    /*!
     * \def HKDS_SYSTEM_OS_SUNUX
     * \brief Defined when the target operating system is Solaris.
     */
#		define HKDS_SYSTEM_OS_SUNUX
#   endif
#endif

#if defined(__posix) || defined(__posix__) || defined(__USE_POSIX) || defined(_POSIX_VERSION) || defined(HKDS_SYSTEM_OS_APPLE)
  /*!
   * \def HKDS_SYSTEM_OS_POSIX
   * \brief Defined when the operating system is POSIX-compliant.
   */
#	define HKDS_SYSTEM_OS_POSIX
#endif

#if defined(HKDS_SYSTEM_OS_WINDOWS) && defined(HKDS_SYSTEM_COMPILER_MSC)
  /*!
   * \def HKDS_WINDOWS_VSTUDIO_BUILD
   * \brief Defined when building on Windows using Visual Studio.
   */
#   define HKDS_WINDOWS_VSTUDIO_BUILD
#endif

#if defined(_OPENMP)
  /*!
   * \def HKDS_SYSTEM_OPENMP
   * \brief Defined when OpenMP support is enabled.
   */
#	define HKDS_SYSTEM_OPENMP
#endif

#if defined(DEBUG) || defined(_DEBUG) || defined(__DEBUG__) || (defined(__GNUC__) && !defined(__OPTIMIZE__))
  /*!
   * \def HKDS_DEBUG_MODE
   * \brief Defined when the build is in debug mode.
   */
#	define HKDS_DEBUG_MODE
#endif

#ifdef HKDS_DEBUG_MODE
#  define HKDS_ASSERT(expr)  assert(expr)
#else
#  define HKDS_ASSERT(expr)  ((void)0)
#endif

/*==============================================================================
    CPU Architecture Identification Macros
==============================================================================*/
#if defined(HKDS_SYSTEM_COMPILER_MSC)
#   if defined(_M_X64) || defined(_M_AMD64)
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86_64
     * \brief Defined when building for 64-bit x86 (AMD64/Intel 64).
     */
#		define HKDS_SYSTEM_ARCH_IX86_64
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86
     * \brief Also defined when building for x86 architectures.
     */
#		define HKDS_SYSTEM_ARCH_IX86
#   if defined(_M_AMD64)
      /*!
       * \def HKDS_SYSTEM_ARCH_AMD64
       * \brief Defined when the processor is AMD64.
       */
#			define HKDS_SYSTEM_ARCH_AMD64
#   endif
#   elif defined(_M_IX86) || defined(_X86_)
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86_32
     * \brief Defined when building for 32-bit x86.
     */
#		define HKDS_SYSTEM_ARCH_IX86_32
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86
     * \brief Also defined for x86 architectures.
     */
#		define HKDS_SYSTEM_ARCH_IX86
#   elif defined(_M_ARM)
    /*!
     * \def HKDS_SYSTEM_ARCH_ARM
     * \brief Defined when building for ARM architectures.
     */
#		define HKDS_SYSTEM_ARCH_ARM
#       if defined(_M_ARM_ARMV7VE)
      /*!
       * \def HKDS_SYSTEM_ARCH_ARMV7VE
       * \brief Defined when building for ARM V7VE.
       */
#			define HKDS_SYSTEM_ARCH_ARMV7VE
#       elif defined(_M_ARM_FP)
      /*!
       * \def HKDS_SYSTEM_ARCH_ARMFP
       * \brief Defined when building for ARM with floating point support.
       */
#			define HKDS_SYSTEM_ARCH_ARMFP
#       elif defined(_M_ARM64)
      /*!
       * \def HKDS_SYSTEM_ARCH_ARM64
       * \brief Defined when building for ARM64.
       */
#			define HKDS_SYSTEM_ARCH_ARM64
#       endif
#   elif defined(_M_IA64)
    /*!
     * \def HKDS_SYSTEM_ARCH_IA64
     * \brief Defined when building for Itanium (IA-64).
     */
#		define HKDS_SYSTEM_ARCH_IA64
#   endif
#elif defined(HKDS_SYSTEM_COMPILER_GCC)
#   if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86_64
     * \brief Defined when building for 64-bit x86 (AMD64/Intel 64) using GCC.
     */
#		define HKDS_SYSTEM_ARCH_IX86_64
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86
     * \brief Also defined for x86 architectures.
     */
#		define HKDS_SYSTEM_ARCH_IX86
#       if defined(_M_AMD64)
      /*!
       * \def HKDS_SYSTEM_ARCH_AMD64
       * \brief Defined when the processor is AMD64.
       */
#			define HKDS_SYSTEM_ARCH_AMD64
#       endif
#   elif defined(i386) || defined(__i386) || defined(__i386__)
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86_32
     * \brief Defined when building for 32-bit x86 using GCC.
     */
#		define HKDS_SYSTEM_ARCH_IX86_32
    /*!
     * \def HKDS_SYSTEM_ARCH_IX86
     * \brief Also defined for x86 architectures.
     */
#		define HKDS_SYSTEM_ARCH_IX86
#   elif defined(__arm__)
    /*!
     * \def HKDS_SYSTEM_ARCH_ARM
     * \brief Defined when building for ARM architectures using GCC.
     */
#		define HKDS_SYSTEM_ARCH_ARM
#       if defined(__aarch64__)
      /*!
       * \def HKDS_SYSTEM_ARCH_ARM64
       * \brief Defined when building for ARM64.
       */
#			define HKDS_SYSTEM_ARCH_ARM64
#       endif
#   elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
    /*!
     * \def HKDS_SYSTEM_ARCH_IA64
     * \brief Defined when building for Itanium (IA-64) using GCC.
     */
#		define HKDS_SYSTEM_ARCH_IA64
#   elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
    /*!
     * \def HKDS_SYSTEM_ARCH_PPC
     * \brief Defined when building for PowerPC 64-bit.
     */
#		define HKDS_SYSTEM_ARCH_PPC
#   elif defined(__sparc) || defined(__sparc__)
    /*!
     * \def HKDS_SYSTEM_ARCH_SPARC
     * \brief Defined when building for SPARC architectures.
     */
#		define HKDS_SYSTEM_ARCH_SPARC
#       if defined(__sparc64__)
      /*!
       * \def HKDS_SYSTEM_ARCH_SPARC64
       * \brief Defined when building for 64-bit SPARC.
       */
#			define HKDS_SYSTEM_ARCH_SPARC64
#       endif
#   endif
#endif

/*==============================================================================
    Sockets and Other System Macros
==============================================================================*/

#if defined(_WIN64) || defined(_WIN32) || defined(__CYGWIN__)
  /*!
   * \def HKDS_SYSTEM_SOCKETS_WINDOWS
   * \brief Defined when using Windows sockets.
   */
#	define HKDS_SYSTEM_SOCKETS_WINDOWS
#else
  /*!
   * \def HKDS_SYSTEM_SOCKETS_BERKELY
   * \brief Defined when using Berkeley sockets.
   */
#	define HKDS_SYSTEM_SOCKETS_BERKELY
#endif

#if defined(__attribute__)
#   define HKDS_ATTRIBUTE __attribute__
#else
#   define HKDS_ATTRIBUTE(a)
#endif

#if defined(_DLL)
  /*!
   * \def HKDS_DLL_API
   * \brief Defined when building as a DLL.
   */
#	define HKDS_DLL_API
#endif

/*!
* \def HKDS_EXPORT_API
* \brief API export macro for Microsoft compilers when importing from a DLL.
*/
#if defined(HKDS_DLL_API)

#if defined(HKDS_SYSTEM_COMPILER_MSC)
#   if defined(HKDS_DLL_IMPORT)
#		define HKDS_EXPORT_API __declspec(dllimport)
#   else
#	    define HKDS_EXPORT_API __declspec(dllexport)
#   endif
#elif defined(HKDS_SYSTEM_COMPILER_GCC)
#   if defined(HKDS_DLL_IMPORT)
#		define HKDS_EXPORT_API HKDS_ATTRIBUTE((dllimport))
#   else
#		define HKDS_EXPORT_API HKDS_ATTRIBUTE((dllexport))
#   endif
#else
#   if defined(__SUNPRO_C)
#       if !defined(__GNU_C__)
#		    define HKDS_EXPORT_API HKDS_ATTRIBUTE (visibility(__global))
#       else
#			define HKDS_EXPORT_API HKDS_ATTRIBUTE __global
#       endif
#   elif defined(_MSG_VER)
#		define HKDS_EXPORT_API extern __declspec(dllexport)
#   else
#		define HKDS_EXPORT_API HKDS_ATTRIBUTE ((visibility ("default")))
#   endif
#endif
#else
#	define HKDS_EXPORT_API
#endif

/*!
* \def HKDS_CACHE_ALIGNED
* \brief Defines cache-line alignment using GCC's HKDS_ATTRIBUTE syntax.
*/
#if defined(__GNUC__)
#	define HKDS_CACHE_ALIGNED HKDS_ATTRIBUTE((aligned(64)))
#elif defined(_MSC_VER)
#	define HKDS_CACHE_ALIGNED __declspec(align(64U))
#endif

#if defined(HKDS_SYSTEM_ARCH_IX86_64) || defined(HKDS_SYSTEM_ARCH_ARM64) || defined(HKDS_SYSTEM_ARCH_IA64) || defined(HKDS_SYSTEM_ARCH_AMD64) || defined(HKDS_SYSTEM_ARCH_SPARC64)
  /*!
   * \def HKDS_SYSTEM_IS_X64
   * \brief Defined when the target system is 64-bit.
   */
#	define HKDS_SYSTEM_IS_X64
#else
  /*!
   * \def HKDS_SYSTEM_IS_X86
   * \brief Defined when the target system is 32-bit.
   */
#	define HKDS_SYSTEM_IS_X86
#endif

#if defined(HKDS_SYSTEM_IS_X64)
  /*!
   * \def HKDS_SIZE_MAX
   * \brief The maximum integer size for a 64-bit system.
   */
#	define HKDS_SIZE_MAX UINT64_MAX
#else
  /*!
   * \def HKDS_SIZE_MAX
   * \brief The maximum integer size for a 32-bit system.
   */
#	define HKDS_SIZE_MAX UINT32_MAX
#endif

/*!
 * \def HKDS_SYSTEM_IS_LITTLE_ENDIAN
 * \brief Defined if the system is little endian.
 */
#if !defined(__BIG_ENDIAN__)
#   if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#       define HKDS_SYSTEM_IS_LITTLE_ENDIAN 1U
#   elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#       define HKDS_SYSTEM_IS_LITTLE_ENDIAN 0U
#   elif defined(_WIN32) || defined(__LITTLE_ENDIAN__)
#       define HKDS_SYSTEM_IS_LITTLE_ENDIAN 1U
#   endif
#endif

#if (!defined(HKDS_SYSTEM_IS_LITTLE_ENDIAN))
#	if defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || (defined(__MWERKS__) && !defined(__INTEL__))
    /*!
     * \def HKDS_SYSTEM_IS_BIG_ENDIAN
     * \brief Defined if the system is big endian.
     */
#		define HKDS_SYSTEM_IS_BIG_ENDIAN
#	else
    /*!
     * \def HKDS_SYSTEM_IS_LITTLE_ENDIAN
     * \brief Defined if the system is little endian.
     */
#		define HKDS_SYSTEM_IS_LITTLE_ENDIAN
#	endif
#endif

/*!
* \def HKDS_ALIGN(x)
* \brief Macro for aligning data to 'x' bytes using GCC/Clang.
*/
#if !defined(HKDS_ALIGN)
#	if defined(__GNUC__) || defined(__clang__)
#		define HKDS_ALIGN(x)  __attribute__((aligned(x)))
#	elif defined(_MSC_VER)
#		define HKDS_ALIGN(x)  __declspec(align(x))
#	else
#		define HKDS_ALIGN(x)
#	endif
#endif

#if defined(__SIZEOF_INT128__) && defined(HKDS_SYSTEM_IS_X64) && !defined(__xlc__) && !defined(uint128_t)
  /*!
   * \def HKDS_SYSTEM_NATIVE_UINT128
   * \brief Defined when the system supports a native 128-bit integer type.
   */
#	define HKDS_SYSTEM_NATIVE_UINT128
#	if defined(__GNUC__)
    /*!
     * \typedef uint128_t
     * \brief A 128-bit unsigned integer type using GCC's mode(TI) attribute.
     */
		typedef uint32_t uint128_t HKDS_ATTRIBUTE((mode(TI)));
#	else
		typedef __int128 uint128_t;
#	endif
#endif

/*!
* \def HKDS_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)
* \brief Performs fast 64-bit multiplication using a native 128-bit integer.
*/
#if defined(HKDS_SYSTEM_NATIVE_UINT128)
#	define HKDS_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
      const uint128_t r = (uint128_t)(X) * (Y);	\
      *(High) = (r >> 64) & 0xFFFFFFFFFFFFFFFFULL;			\
      *(Low) = (r) & 0xFFFFFFFFFFFFFFFFULL;					\
	} while(0U)
#elif defined(HKDS_SYSTEM_COMPILER_MSC) && defined(HKDS_SYSTEM_IS_X64)
#	include <intrin.h>
#	pragma intrinsic(_umul128)
#	define HKDS_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
		*(Low) = _umul128((X), (Y), (High));				\
	} while(0U)
#elif defined(HKDS_SYSTEM_COMPILER_GCC)
#	if defined(HKDS_SYSTEM_ARCH_IX86)
#		define HKDS_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							    \
		do {																	    \
		asm("mulq %3" : "=d" (*(High)), "=X" (*(Low)) : "X" (X), "rm" (Y) : "cc");	\
		} while(0U)
#	elif defined(HKDS_SYSTEM_ARCH_ALPHA)
#		define HKDS_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("umulh %1,%2,%0U" : "=r" (*(High)) : "r" (X), "r" (Y));				\
		*(Low) = (X) * (Y);														\
		} while(0U)
#	elif defined(HKDS_SYSTEM_ARCH_IA64)
#		define HKDS_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("xmpy.hu %0U=%1,%2" : "=f" (*(High)) : "f" (X), "f" (Y));			\
		*(Low) = (X) * (Y);														\
		} while(0U)
#	elif defined(HKDS_SYSTEM_ARCH_PPC)
#		define HKDS_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("mulhdu %0U,%1,%2" : "=r" (*(High)) : "r" (X), "r" (Y) : "cc");		\
		*(Low) = (X) * (Y);														\
		} while(0U)
#	endif
#endif

/*!
 * \def HKDS_SYSTEM_MAX_PATH
 * \brief The maximum path length supported by the system.
 */
#define HKDS_SYSTEM_MAX_PATH 260ULL

/*!
 * \def HKDS_SYSTEM_SECMEMALLOC_DEFAULT
 * \brief Default secure memory buffer allocation size (in bytes).
 */
#define HKDS_SYSTEM_SECMEMALLOC_DEFAULT 4096ULL

/*!
 * \def HKDS_SYSTEM_SECMEMALLOC_MIN
 * \brief Minimum secure memory allocation size (in bytes).
 */
#define HKDS_SYSTEM_SECMEMALLOC_MIN 16ULL

/*!
 * \def HKDS_SYSTEM_SECMEMALLOC_MAX
 * \brief Maximum secure memory allocation size (in bytes).
 */
#define HKDS_SYSTEM_SECMEMALLOC_MAX 128ULL

/*!
 * \def HKDS_SYSTEM_SECMEMALLOC_MAXKB
 * \brief Maximum secure memory allocation in kilobytes.
 */
#define HKDS_SYSTEM_SECMEMALLOC_MAXKB 512ULL

#if defined(_WIN32)
  /*!
   * \def HKDS_SYSTEM_VIRTUAL_LOCK
   * \brief Defined if the system supports virtual memory locking on Windows.
   */
#	define HKDS_SYSTEM_VIRTUAL_LOCK

  /*!
   * \def HKDS_RTL_SECURE_MEMORY
   * \brief Defined if the system supports secure memory allocation on Windows.
   */
#	define HKDS_RTL_SECURE_MEMORY
#endif

#if defined(_POSIX_MEMLOCK_RANGE)
  /*!
   * \def HKDS_SYSTEM_POSIX_MLOCK
   * \brief Defined if the system supports the POSIX mlock function.
   */
#	define HKDS_SYSTEM_POSIX_MLOCK
#endif

#if defined(HKDS_SYSTEM_VIRTUAL_LOCK) || defined(HKDS_SYSTEM_POSIX_MLOCK)
  /*!
   * \def HKDS_SYSTEM_SECURE_ALLOCATOR
   * \brief Defined if the system has a secure memory allocator.
   */
#	define HKDS_SYSTEM_SECURE_ALLOCATOR
#endif

/*!
* \def HKDS_SYSTEM_OPTIMIZE_IGNORE
* \brief Compiler hint to disable optimization in MSVC.
*/
#if defined(HKDS_SYSTEM_COMPILER_MSC)
#	define HKDS_SYSTEM_OPTIMIZE_IGNORE __pragma(optimize("", off))
#elif defined(HKDS_SYSTEM_COMPILER_GCC) || defined(HKDS_SYSTEM_COMPILER_MINGW)
#   if defined(__clang__)
    /*!
     * \def HKDS_SYSTEM_OPTIMIZE_IGNORE
     * \brief Compiler hint to disable optimization in Clang.
     */
#		define HKDS_SYSTEM_OPTIMIZE_IGNORE HKDS_ATTRIBUTE((optnone))
#   else
    /*!
     * \def HKDS_SYSTEM_OPTIMIZE_IGNORE
     * \brief Compiler hint to disable optimization in GCC.
     */
#		define HKDS_SYSTEM_OPTIMIZE_IGNORE HKDS_ATTRIBUTE((optimize("O0")))
#   endif
#elif defined(HKDS_SYSTEM_COMPILER_CLANG)
  /*!
   * \def HKDS_SYSTEM_OPTIMIZE_IGNORE
   * \brief Compiler hint to disable optimization in Clang.
   */
#	define HKDS_SYSTEM_OPTIMIZE_IGNORE HKDS_ATTRIBUTE((optnone))
#elif defined(HKDS_SYSTEM_COMPILER_INTEL)
  /*!
   * \def HKDS_SYSTEM_OPTIMIZE_IGNORE
   * \brief Compiler hint to disable optimization in the Intel compiler.
   */
#	define HKDS_SYSTEM_OPTIMIZE_IGNORE pragma optimize("", off)
#else
#	define HKDS_SYSTEM_OPTIMIZE_IGNORE
#endif

/*!
* \def HKDS_SYSTEM_OPTIMIZE_RESUME
* \brief Compiler hint to resume optimization in MSVC.
*/
#if defined(HKDS_SYSTEM_COMPILER_MSC)
#	define HKDS_SYSTEM_OPTIMIZE_RESUME __pragma(optimize("", on))
#elif defined(HKDS_SYSTEM_COMPILER_GCC) || defined(HKDS_SYSTEM_COMPILER_MINGW)
#   if defined(__clang__)
#		define HKDS_SYSTEM_OPTIMIZE_RESUME
#   else
#		define HKDS_SYSTEM_OPTIMIZE_RESUME _Pragma("GCC diagnostic pop")
#   endif
#elif defined(HKDS_SYSTEM_COMPILER_INTEL)
#	define HKDS_SYSTEM_OPTIMIZE_RESUME pragma optimize("", on)
#else
#	define HKDS_SYSTEM_OPTIMIZE_RESUME
#endif

/*!
* \def HKDS_SYSTEM_CONDITION_IGNORE(x)
* \brief MSVC-specific macro to disable a specific warning condition.
*/
#if defined(HKDS_SYSTEM_COMPILER_MSC)
#	define HKDS_SYSTEM_CONDITION_IGNORE(x) __pragma(warning(disable : x))
#elif defined(HKDS_SYSTEM_COMPILER_GCC) || defined(HKDS_SYSTEM_COMPILER_MINGW)
#	define HKDS_SYSTEM_CONDITION_IGNORE(x) _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wunused-parameter\"")
#elif defined(HKDS_SYSTEM_COMPILER_INTEL)
#	define HKDS_SYSTEM_CONDITION_IGNORE(x)
#else
#	define HKDS_SYSTEM_CONDITION_IGNORE(x)
#endif

#if (_MSC_VER >= 1600)
  /*!
   * \def HKDS_WMMINTRIN_H
   * \brief Defined when the CPU supports SIMD instructions (MSVC).
   */
#	define HKDS_WMMINTRIN_H 1
#endif

#if (_MSC_VER >= 1700) && (defined(_M_X64))
  /*!
   * \def HKDS_HAVE_AVX2INTRIN_H
   * \brief Defined when the CPU supports AVX2 (MSVC, 64-bit).
   */
#	define HKDS_HAVE_AVX2INTRIN_H 1
#endif

/*==============================================================================
    AVX512 Capabilities
==============================================================================*/

/* Enable this define to support AVX512 on a compatible system */
/*#define CEX_AVX512_SUPPORTED*/

#if defined(__AVX512F__) && (__AVX512F__ == 1)
  /*!
   * \def __AVX512__
   * \brief Defined when the system supports AVX512 instructions.
   */
#	include <immintrin.h>
#	if (!defined(__AVX512__))
#		define __AVX512__
#	endif
#endif

#if defined(__SSE2__)
  /*!
   * \def HKDS_SYSTEM_HAS_SSE2
   * \brief Defined if the system supports SSE2 instructions.
   */
#	define HKDS_SYSTEM_HAS_SSE2
#endif

#if defined(__SSE3__)
  /*!
   * \def HKDS_SYSTEM_HAS_SSE3
   * \brief Defined if the system supports SSE3 instructions.
   */
#	define HKDS_SYSTEM_HAS_SSE3
#endif

#if defined(__SSSE3__)
  /*!
   * \def HKDS_SYSTEM_HAS_SSSE3
   * \brief Defined if the system supports SSSE3 instructions.
   */
#	define HKDS_SYSTEM_HAS_SSSE3
#endif

#if defined(__SSE4_1__)
  /*!
   * \def HKDS_SYSTEM_HAS_SSE41
   * \brief Defined if the system supports SSE4.1 instructions.
   */
#	define HKDS_SYSTEM_HAS_SSE41
#endif

#if defined(__SSE4_2__)
  /*!
   * \def HKDS_SYSTEM_HAS_SSE42
   * \brief Defined if the system supports SSE4.2 instructions.
   */
#	define HKDS_SYSTEM_HAS_SSE42
#endif

#if defined(__ARM_NEON__)
#   define HKDS_SYSTEM_HAS_ARM_NEON
#endif

#if defined(__AVX__)
  /*!
   * \def HKDS_SYSTEM_HAS_AVX
   * \brief Defined if the system supports AVX instructions.
   */
#	define HKDS_SYSTEM_HAS_AVX
#endif

#if defined(__AVX2__)
  /*!
   * \def HKDS_SYSTEM_HAS_AVX2
   * \brief Defined if the system supports AVX2 instructions.
   */
#	define HKDS_SYSTEM_HAS_AVX2
#endif

#if defined(__AVX512__)
  /*!
   * \def HKDS_SYSTEM_HAS_AVX512
   * \brief Defined if the system supports AVX512 instructions.
   * \warning: MSVC (and possibly other compilers) silently promote AVX2 intrinsics when 
   * AVX512 is enabled, causing failures in release mode builds of implementations using AVX2.
   * It is an 'either/or' situation, if you  really need AVX512, split out the implementation from the library,
   * the symmetric ciphers and SHA3 work fine in AVX512 alone, but AVX512 will break Dilithium, Kyber, 
   * anything else using AVX2 intrinsics.
   */
#	define HKDS_SYSTEM_HAS_AVX512
#endif

#if defined(__XOP__)
  /*!
   * \def HKDS_SYSTEM_HAS_XOP
   * \brief Defined if the system supports XOP instructions.
   */
#	define HKDS_SYSTEM_HAS_XOP
#endif

#if defined(HKDS_SYSTEM_HAS_AVX) || defined(HKDS_SYSTEM_HAS_AVX2) || defined(HKDS_SYSTEM_HAS_AVX512)
  /*!
   * \def HKDS_SYSTEM_AVX_INTRINSICS
   * \brief Defined if the system supports AVX intrinsics.
   */
#	define HKDS_SYSTEM_AVX_INTRINSICS
#endif

/*==============================================================================
    Assembly and SIMD Alignment Macros
==============================================================================*/

/*!
* \def HKDS_ASM_ENABLED
* \brief Global flag for enabling ASM compilation (user-modifiable).
*/
/*#define HKDS_ASM_ENABLED */

/*!
* \def HKDS_MISRA_FULL_COMPLIANCE
* \brief Enable full MISRA compliant cryptographic module compliance.
*/
#define HKDS_MISRA_FULL_COMPLIANCE

#if defined(HKDS_SYSTEM_AVX_INTRINSICS) && defined(HKDS_SYSTEM_COMPILER_GCC) && defined(HKDS_ASM_ENABLED)
  // #define HKDS_GCC_ASM_ENABLED  /* Uncomment to enable GCC ASM processing */
#endif

  /*!
   * \def HKDS_SIMD_ALIGNMENT
   * \brief Alignment value for enabled intrinsic.
   */
#if defined(HKDS_SYSTEM_HAS_AVX512)
#  define HKDS_SIMD_ALIGNMENT 64
#elif defined(HKDS_SYSTEM_HAS_AVX2)
#  define HKDS_SIMD_ALIGNMENT 32
#elif defined(HKDS_SYSTEM_HAS_AVX)
#  define HKDS_SIMD_ALIGNMENT 16
#else
#  define HKDS_SIMD_ALIGNMENT 8
#endif

  /*!
   * \def HKDS_SIMD_ALIGN
   * \brief Macro to align data on supported intrinsics size
   */
#if defined(_MSC_VER)
#  define HKDS_SIMD_ALIGN __declspec(align(HKDS_SIMD_ALIGNMENT))
#elif defined(__GNUC__) || defined(__clang__)
#  define HKDS_SIMD_ALIGN _Alignas(HKDS_SIMD_ALIGNMENT)
#else
#  define HKDS_SIMD_ALIGN
#endif

#if defined(HKDS_SYSTEM_AVX_INTRINSICS)
  /*!
   * \def HKDS_RDRAND_COMPATIBLE
   * \brief Defined if the CPU is RDRAND compatible.
   */
#	define HKDS_RDRAND_COMPATIBLE
#endif

/*!
 * \def HKDS_STATUS_SUCCESS
 * \brief Function return value indicating successful operation.
 */
#define HKDS_STATUS_SUCCESS 0LL

/*!
 * \def HKDS_STATUS_FAILURE
 * \brief Function return value indicating failed operation.
 */
#define HKDS_STATUS_FAILURE -1LL

/*==============================================================================
    User Modifiable Values and Cryptographic Parameter Sets
==============================================================================*/

#if !defined(HKDS_SYSTEM_AESNI_ENABLED)
#	if defined(HKDS_SYSTEM_AVX_INTRINSICS)
    /*!
     * \def HKDS_SYSTEM_AESNI_ENABLED
     * \brief Enable the use of intrinsics and the AES-NI implementation.
     */
#		define HKDS_SYSTEM_AESNI_ENABLED
#	endif
#endif

///*!
// * \def HKDS_KECCAK_UNROLLED_PERMUTATION
// * \brief Define to use the unrolled form of the Keccak permutation function.
// */
//#define HKDS_KECCAK_UNROLLED_PERMUTATION

/* \endcond */


HKDS_CPLUSPLUS_ENABLED_END

#endif
