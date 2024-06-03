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
void hkdstest_benchmark_hkds_server_run(void);

/**
* \brief Tests the HKDS client encryption performance.
* Tests the clients encryption function for performance timing.
*/
void hkdstest_benchmark_hkds_client_run(void);

/**
* \brief Tests the KMAC implementations performance.
* Tests the Keccak MACs for performance timing.
*/
void hkdstest_benchmark_kmac_run(void);

/**
* \brief Tests the SHAKE implementations performance.
* Tests the various SHAKE implementations for performance timing.
*/
void hkdstest_benchmark_shake_run(void);

#endif