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
 * Contact: contact@qrcscorp.ca
 */

#ifndef HKDS_UTILS_H
#define HKDS_UTILS_H

#include "common.h"

/**
* \internal
* \file utils.h
* \brief This file contains utility definitions
*/

/*!
* \def HKDS_STRINGUTILS_TOKEN_NOT_FOUND
* \brief The search token was not found
*/
#define UTILS_TOKEN_NOT_FOUND -1

/*!
* \def UTILS_STRING_MAX_LEN
* \brief The string maximum length
*/
#define UTILS_STRING_MAX_LEN 4096

/*!
* \def HKDS_CSP_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
#define UTILS_SEED_MAX 1024000

/* pseudo-random generation */

/**
* \brief Get an array of pseudo-random bytes from the system entropy provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
HKDS_EXPORT_API bool utils_seed_generate(uint8_t* output, size_t length);

/* console functions */

/**
* \brief Convert a hexadecimal character string to a character byte array
*
* \param hexstr: [const] The string to convert
* \param output: The character output array
* \param length: The number of characters to convert
*/
HKDS_EXPORT_API void utils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Print an array of characters to the console
*
* \param input: [const] The character array to print
*/
HKDS_EXPORT_API void utils_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: [const] The character array to print
*/
HKDS_EXPORT_API void utils_print_line(const char* input);

/* timer functions */

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
HKDS_EXPORT_API uint64_t utils_stopwatch_start(void);

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The time difference in milliseconds
*/
HKDS_EXPORT_API uint64_t utils_stopwatch_elapsed(uint64_t start);

/* string functions */

/**
* \brief Find a substrings position within a string
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns the character position within the string, or HKDS_STRINGUTILS_TOKEN_NOT_FOUND if the string is not found
*/
HKDS_EXPORT_API int64_t utils_find_string(const char* source, const char* token);

/**
* \brief Test if the string contains a substring
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns true if the substring is found
*/
HKDS_EXPORT_API bool utils_string_contains(const char* source, const char* token);

/**
* \brief Get the character length of a string
*
* \param source: [const] The source string pointer
* \return Returns the size of the string
*/
HKDS_EXPORT_API size_t utils_string_size(const char* source);

/**
* \brief Convert a string to all lower-case characters
*
* \param source: The string to convert to lower-case
*/
HKDS_EXPORT_API void utils_string_to_lowercase(char* source);

/* memory functions */

/**
* \brief Erase a block of memory
*
* \param output: A pointer to the memory block to erase
* \param length: The number of bytes to erase
*/
HKDS_EXPORT_API void utils_memory_clear(void* output, size_t length);

/**
* \brief Free an aligned memory block
*
* \param block: A pointer to the memory block to release
*/
HKDS_EXPORT_API void utils_memory_aligned_free(void* block);

/**
* \brief Allocate an aligned 8-bit integer array
*
* \param align: The memory alignment boundary
* \param length: The length of the requested block
*
* \return Returns the aligned array of bytes, or NULL on failure
*/
HKDS_EXPORT_API void* utils_memory_aligned_alloc(int32_t align, size_t length);

/**
* \brief Compare two byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
* \param length: The number of bytes to compare
*
* \return Returns if the arrays are equivalent
*/
HKDS_EXPORT_API bool utils_memory_are_equal(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Compare two 16 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
HKDS_EXPORT_API bool utils_memory_are_equal_128(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 32 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
HKDS_EXPORT_API bool utils_memory_are_equal_256(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 64 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
HKDS_EXPORT_API bool utils_memory_are_equal_512(const uint8_t* a, const uint8_t* b);

/**
* \brief Copy a block of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to copy
*/
HKDS_EXPORT_API void utils_memory_copy(void* output, const void* input, size_t length);

/**
* \brief Bitwise XOR two blocks of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to XOR
*/
HKDS_EXPORT_API void utils_memory_xor(uint8_t* output, const uint8_t* input, size_t length);

/* integer functions */

/**
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit big endian integer
*/
HKDS_EXPORT_API uint32_t utils_integer_be8to32(const uint8_t* input);

/**
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 32-bit integer
*/
HKDS_EXPORT_API void utils_integer_be32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit little endian integer
*/
HKDS_EXPORT_API uint64_t utils_integer_le8to64(const uint8_t* input);

/**
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 64-bit integer
*/
HKDS_EXPORT_API void utils_integer_le64to8(uint8_t* output, uint64_t value);

/**
* \brief Increment an 8-bit integer array as a segmented big-endian integer
*
* \param output: The destination integer 8-bit array
* \param otplen: The length of the output counter array
*/
HKDS_EXPORT_API void utils_integer_be8increment(uint8_t* output, size_t otplen);

/**
* \brief Rotate an unsigned 64-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
HKDS_EXPORT_API uint64_t utils_integer_rotl64(uint64_t value, size_t shift);

/**
* \brief Constant time comparison of two arrays of unsigned 8-bit integers
*
* \param a: [const] The first 8-bit integer array
* \param b: [const] The second 8-bit integer array
* \param length: The number of bytes to check
* \return Returns zero if the arrays are equivalent
*/
HKDS_EXPORT_API int32_t utils_integer_verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
