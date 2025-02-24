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

#ifndef HKDSTEST_HKDSTEST_H
#define HKDSTEST_HKDSTEST_H

#include "common.h"

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
