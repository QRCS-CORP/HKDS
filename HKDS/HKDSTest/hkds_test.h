#ifndef HKDSTEST_HKDSTEST_H
#define HKDSTEST_HKDSTEST_H

#include "common.h"

/**
* \brief Tests full cycles of the sever to client interaction
*
* \return Returns true for test success
*/
bool hkds_cycle_test();

/**
* \brief Tests against known answer values for operational correctness
*
* \return Returns true for test success
*/
bool hkds_kat_test();

/**
* \brief Tests the authenticated encryption against known answer values for operational correctness
*
* \return Returns true for test success
*/
bool hkds_katae_test();

/**
* \brief Runs a looping known answer test
*
* \return Returns true for test success
*/
bool monte_carlo_test();

/**
* \brief Tests the server and client modes in a loop for operational correctness
*
* \return Returns true for test success
*/
bool hkds_stress_test();

/**
* \brief Tests the SIMD server encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkds_simd_encrypt_equivalence_test();

/**
* \brief Tests the parallel server encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkds_parallel_encrypt_equivalence_test();

/**
* \brief Tests the SIMD server authentication and encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkds_simd_authencrypt_equivalence_test();

/**
* \brief Tests the parallel server authentication and encryption for operational correctness
*
* \return Returns true for test success
*/
bool hkds_parallel_authencrypt_equivalence_test();

/**
* \brief Run all tests
*/
void hkds_test_run();

#endif