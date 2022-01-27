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

#ifndef HKDS_COMMON_H
#define HKDS_COMMON_H

#include <assert.h>
//#include <intrin.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#if !defined(__clang__) && !defined(__GNUC__)
#	ifdef __attribute__
#		undef __attribute__
#	endif
#	define __attribute__(a)
#endif

#if defined(_DLL)
#	define HKDS_DLL_API
#endif

#if defined(HKDS_DLL_API)
#	if defined(_MSC_VER)
#		if defined(HKDS_DLL_IMPORT)
#			define HKDS_EXPORT_API __declspec(dllimport)
#		else
#			define HKDS_EXPORT_API __declspec(dllexport)
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define HKDS_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define HKDS_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define HKDS_EXPORT_API extern __declspec(dllexport)
#		else
#			define HKDS_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define HKDS_EXPORT_API
#endif

#endif
