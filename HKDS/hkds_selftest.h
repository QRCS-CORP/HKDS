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

#ifndef HKDS_SELFTEST_H
#define HKDS_SELFTEST_H

#include "common.h"

/** 
 * \file hkds_selftest.h
 * \brief This file contains HKDS self-test definitions.
 *
 * \details
 * This header defines the self-test function for the HKDS library. The self-test validates the
 * correctness of the symmetric cryptographic primitives implemented within the library (including
 * various SHAKE and KMAC variants) by comparing computed outputs against predetermined known-answer
 * test vectors. Successful execution of these tests ensures that the cryptographic functions are
 * operating as expected.
 */

/**
 * \brief Runs the library self tests.
 *
 * \details
 * This function executes a comprehensive suite of self-tests for the symmetric primitives used in HKDS.
 * The tests cover:
 * - Known-answer tests for SHAKE-128, SHAKE-256, and SHAKE-512.
 * - Known-answer tests for KMAC with different security parameters (e.g., KMAC-128, KMAC-256, and KMAC-512).
 * - Additional equality tests for vectorized implementations (if supported by the system, such as AVX2/AVX512).
 *
 * The function returns true if all tests pass successfully, indicating that the library's cryptographic
 * functions are correctly implemented. Otherwise, it returns false.
 *
 * \return Returns true if all tests pass successfully; otherwise, false.
 */
HKDS_EXPORT_API bool hkds_selftest_symmetric_run(void);

#endif
