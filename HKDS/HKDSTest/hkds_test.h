// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2024 QRCS Corp.
// This file is part of the HKDS test suite.
// 
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef HKDSTEST_HKDSTEST_H
#define HKDSTEST_HKDSTEST_H

#include "common.h"

/**
* \brief Tests full cycles of the sever to client interaction
*
* \return Returns true for test success
*/
bool hkdstest_cycle_test(void);

/**
* \brief Tests against known answer values for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_kat_test(void);

/**
* \brief Tests the authenticated encryption against known answer values for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_katae_test(void);

/**
* \brief Runs a looping known answer test
*
* \return Returns true for test success
*/
bool hkdstest_monte_carlo_test(void);

/**
* \brief Tests the server and client modes in a loop for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_stress_test(void);

/**
* \brief Tests the SIMD server encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_simd_encrypt_equivalence_test(void);

/**
* \brief Tests the SIMD server authentication and encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_simd_authencrypt_equivalence_test(void);

#if defined(SYSTEM_OPENMP)

/**
* \brief Tests the parallel server encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_parallel_encrypt_equivalence_test(void);

/**
* \brief Tests the parallel server authentication and encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_parallel_authencrypt_equivalence_test(void);


#endif
/**
* \brief Run all tests
*/
void hkdstest_test_run(void);

#endif
