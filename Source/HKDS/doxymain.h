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

#ifndef HKDS_DOXYMAIN_H
#define HKDS_DOXYMAIN_H

/**
 * \mainpage HKDS Protocol Project Documentation
 *
 * \section intro_sec Introduction
 * 
 * The HKDS Protocol Project implements a Hierarchical Key Derivation System (HKDS) designed to provide a
 * robust and secure mechanism for key management and token exchange between client devices and a transaction
 * processing server. Leveraging cryptographic primitives standardized by NIST (including SHA-3, SHAKE, and KMAC),
 * the HKDS protocol is well-suited for high-security environments such as point-of-sale (POS) systems.
 *
 * \section protocol_sec HKDS Protocol Overview
 *
 * The HKDS protocol is built upon a hierarchical structure for key derivation. Its main components include:
 *
 * - **Master Key Set (MDK):** Comprised of a Base Derivation Key (BDK), a Secret Token Key (STK), and a Key Identity (KID).
 * - **Key Serial Number (KSN):** A unique identifier for each client that encapsulates the device identity (DID) and a token counter.
 * - **Embedded Device Key (EDK):** Derived from the device's unique identity and the BDK, this key is used to generate the
 *   Transaction Key Cache (TKC).
 * - **Transaction Key Cache (TKC):** A set of keys generated from the decrypted token and the EDK. These keys are used for
 *   encrypting and authenticating messages.
 *
 * The protocol employs:
 *  - **SHAKE Functions:** Acting as the primary pseudo-random function (PRF) for generating key streams.
 *  - **KMAC Functions:** Providing message authentication to ensure the integrity of encrypted data.
 *  - **Token Exchange:** A secure process where the server encrypts a token using the STK and a custom token string, and the
 *    client decrypts the token to derive the transaction keys.
 *
 * \section test_sec HKDS Test Project
 *
 * The HKDS Test Project is an extensive suite of tests designed to validate both the functionality and performance of
 * the HKDS implementation. Key test categories include:
 *
 * - **Cycle Tests:** Verify full protocol interactions between the server and client.
 * - **Known-Answer Tests (KAT):** Compare outputs of encryption, decryption, and key derivation operations against pre-computed
 *   expected results.
 * - **Authenticated Encryption Tests (KATAE):** Confirm that the authenticated encryption process produces the correct
 *   ciphertext and MAC tag.
 * - **Monte Carlo Tests:** Run repeated cycles to verify the robustness and consistency of the implementation.
 * - **Stress Tests:** Continuously execute full protocol cycles to assess the system's stability under load.
 * - **SIMD/Parallel Tests:** Validate that vectorized implementations (using SIMD instructions) produce equivalent results
 *   to the sequential versions.
 * - **Benchmark Tests:** Measure the timing performance of the cryptographic primitives and overall protocol operations.
 *
 * \section project_sec Project Structure
 *
 * The project is organized into several modules:
 *
 * - **Client Module (hkds_client.h/.c):** Contains functions for key management, message encryption, and token handling on the client side.
 * - **Server Module (hkds_server.h/.c):** Implements key derivation, token generation, and message decryption for the server.
 * - **Configuration Module (hkds_config.h):** Defines protocol parameters, key sizes, and mode settings.
 * - **Queue Module (hkds_queue.h/.c):** Implements message queuing for asynchronous operations.
 * - **Benchmark Module (hkds_benchmark.h/.c):** Provides performance benchmarking for cryptographic primitives and protocol operations.
 * - **Test Module (hkds_test.h/.c):** Contains comprehensive tests for functional correctness and performance.
 *
 * \section conclusion_sec Conclusion
 *
 * Together, these modules form a complete solution for secure key management and message processing in transactional
 * systems. The HKDS protocol, with its rigorous testing and performance benchmarks, ensures both security and
 * operational efficiency in high-stakes environments. This documentation serves as a guide for understanding, using,
 * and extending the HKDS protocol and its accompanying test suite.
 *
 *
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 * 
 * \author John G. Underhill
 * \date 2025-02-10
 */

#endif