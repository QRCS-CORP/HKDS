/**
* \file symmetric_benchmark.h
* \brief <b>AES and RHX performance benchmarking</b> \n
* Tests the CBC, CTR, AND HBA modes for timimng performance.
* \author John Underhill
* \date November 24, 2020
*/

#ifndef HKDSTEST_BENCHMARK_H
#define HKDSTEST_BENCHMARK_H

#include "common.h"

/**
* \brief Tests the HKDS server implementations performance.
* Tests the server key generation, extraction, and decryption functions for performance timing.
*/
void hkdstest_benchmark_hkds_server_run();

/**
* \brief Tests the HKDS client encryption performance.
* Tests the clients encryption function for performance timing.
*/
void hkdstest_benchmark_hkds_client_run();

/**
* \brief Tests the KMAC implementations performance.
* Tests the Keccak MACs for performance timing.
*/
void hkdstest_benchmark_kmac_run();

/**
* \brief Tests the SHAKE implementations performance.
* Tests the various SHAKE implementations for performance timing.
*/
void hkdstest_benchmark_shake_run();

#endif