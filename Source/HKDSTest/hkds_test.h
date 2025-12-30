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

#ifndef HKDSTEST_HKDSTEST_H
#define HKDSTEST_HKDSTEST_H

#include "hkdscommon.h"

/**
 * \file hkds_test.h
 * \brief This file contains HKDS test definitions.
 *
 * \details
 * This header declares a set of test functions designed to verify the operational correctness
 * of the HKDS library. The tests include full protocol cycles, known-answer tests (KAT),
 * authenticated encryption tests, monte carlo tests, stress tests, and SIMD/parallel equivalence
 * tests. Each test returns a boolean value indicating success or failure.
 */

/**
 * \brief Tests full cycles of the server to client interaction.
 *
 * \details
 * This test runs complete cycles of the HKDS protocol between the server and the client.
 * It simulates the full exchange: the server encrypts a token, the client decrypts the token,
 * derives a transaction key-set, encrypts a message, and finally the server decrypts the message.
 * The test returns true if the decrypted message matches the original plaintext.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_cycle_test(void);

/**
 * \brief Tests against known answer values for operational correctness.
 *
 * \details
 * This test verifies the correctness of the HKDS implementation by comparing computed outputs
 * (such as tokens, ciphertext, and decrypted messages) against predetermined known-answer test
 * vectors.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_kat_test(void);

/**
 * \brief Tests the authenticated encryption against known answer values for operational correctness.
 *
 * \details
 * This test validates the authenticated encryption functionality by comparing the computed
 * ciphertext (including its MAC tag) and the result of decryption against known expected values.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_katae_test(void);

/**
 * \brief Runs a looping known answer test.
 *
 * \details
 * This test repeatedly performs the encryption and decryption process (monte carlo testing)
 * over many cycles to verify the robustness and consistency of the implementation.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_monte_carlo_test(void);

/**
 * \brief Tests the server and client modes in a loop for operational correctness.
 *
 * \details
 * This stress test repeatedly executes full protocol cycles between the server and client to assess
 * the overall stability and correctness under continuous load.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_stress_test(void);

/**
 * \brief Tests the SIMD server encryption for operational correctness.
 *
 * \details
 * This test verifies that the SIMD (parallel) implementation of the server encryption functions
 * produces results equivalent to the sequential implementation.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_simd_encrypt_equivalence_test(void);

/**
 * \brief Tests the SIMD server authentication and encryption for operational correctness.
 *
 * \details
 * This test verifies that the SIMD (parallel) implementation of the server authenticated encryption
 * functions produces results equivalent to the sequential implementation.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_simd_authencrypt_equivalence_test(void);

#if defined(SYSTEM_OPENMP)

/**
 * \brief Tests the parallel server encryption for operational correctness.
 *
 * \details
 * This test verifies the parallel server encryption using the x64 SIMD API. It confirms that the output
 * of the parallel decryption matches the expected results.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_parallel_encrypt_equivalence_test(void);

/**
 * \brief Tests the parallel server authentication and encryption for operational correctness.
 *
 * \details
 * This test verifies the parallel server authenticated encryption using the x64 SIMD API. It confirms that
 * the parallel implementation produces the same decrypted outputs as the sequential version.
 *
 * \return Returns true for test success, false otherwise.
 */
bool hkdstest_parallel_authencrypt_equivalence_test(void);

#endif

/**
 * \brief Runs all HKDS tests.
 *
 * \details
 * This function executes all the HKDS test functions, including cycle tests, known-answer tests,
 * monte carlo tests, stress tests, and SIMD/parallel equivalence tests. Test results are printed,
 * and the overall success or failure is determined based on the individual outcomes.
 */
void hkdstest_test_run(void);

#endif
