/* 2021-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
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
