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

#ifndef HKDSTEST_BENCHMARK_H
#define HKDSTEST_BENCHMARK_H

#include "hkdscommon.h"

/**
 * \file hkds_benchmark.h
 * \brief HKDS performance benchmark tests.
 *
 * \details
 * This header defines functions to benchmark the performance of various HKDS cryptographic operations and
 * primitives. The benchmark tests measure the timing performance for key generation, encryption/decryption,
 * and MAC computations for both the server and client implementations, as well as for the underlying KMAC and
 * SHAKE functions. The tests cover both scalar and vectorized (SIMD) implementations where applicable.
 *
 * The benchmark test suite includes:
 * - \b Server benchmarks: Timing the performance of server key generation, extraction, and decryption operations.
 * - \b Client benchmarks: Timing the performance of the client's message encryption operations.
 * - \b KMAC benchmarks: Measuring the throughput of the KMAC (Keccak-based MAC) implementations.
 * - \b SHAKE benchmarks: Measuring the throughput of the various SHAKE (extendable-output function) implementations.
 */

/**
 * \brief Tests the HKDS server implementation performance.
 *
 * \details
 * This function benchmarks the performance of the HKDS server functions. It tests the server key generation,
 * extraction, and decryption functions over a fixed number of cycles, and prints the total elapsed time.
 */
void hkdstest_benchmark_hkds_server_run(void);

/**
 * \brief Tests the HKDS client encryption performance.
 *
 * \details
 * This function benchmarks the performance of the HKDS client encryption functions. It measures the time required
 * to encrypt a fixed number of messages over multiple iterations.
 */
void hkdstest_benchmark_hkds_client_run(void);

/**
 * \brief Tests the KMAC implementations performance.
 *
 * \details
 * This function benchmarks the performance of the KMAC implementations for various security levels.
 * It processes approximately 1GB of data using KMAC-128, KMAC-256, and KMAC-512 (including vectorized versions,
 * if available) and prints the time taken.
 */
void hkdstest_benchmark_kmac_run(void);

/**
 * \brief Tests the SHAKE implementations performance.
 *
 * \details
 * This function benchmarks the performance of various SHAKE implementations (SHAKE-128, SHAKE-256, and SHAKE-512).
 * It processes approximately 1GB of data using both scalar and vectorized (if available) versions of SHAKE, and prints
 * the timing results.
 */
void hkdstest_benchmark_shake_run(void);

#endif