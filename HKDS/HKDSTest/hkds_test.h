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
* \brief Tests the parallel server encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_parallel_encrypt_equivalence_test(void);

/**
* \brief Tests the SIMD server authentication and encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_simd_authencrypt_equivalence_test(void);

/**
* \brief Tests the parallel server authentication and encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkdstest_parallel_authencrypt_equivalence_test(void);

/**
* \brief Run all tests
*/
void hkdstest_test_run(void);

#endif
