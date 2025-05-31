/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Written on March 29, 2020
 * Updated on May 27, 2025
 * Contact: contact@qrcscorp.ca
 */

#include "hkds_benchmark.h"
#include "hkds_test.h"
#include "testutils.h"
#include "hkdscommon.h"
#include "utils.h"
#include "hkds_config.h"
#include "hkds_selftest.h"
#include <stdlib.h>
#include <stdio.h>

void print_title(void)
{
	hkdstest_print_line("******************************************************");
	hkdstest_print_line("* HKDS: Heirarchal symmetric Key Distribution System *");
	hkdstest_print_line("*                                                    *");
	hkdstest_print_line("* Release:   v1.0.0.2c (A2)                          *");
	hkdstest_print_line("* License:   Copyrighted and Patent pending          *");
	hkdstest_print_line("* Date:      May 31 2025                             *");
	hkdstest_print_line("* Author:    John G. Underhill                       *");
	hkdstest_print_line("* Contact:   contact@qrcscorp.ca					  *");
	hkdstest_print_line("******************************************************");
	hkdstest_print_line("");
}

int main(void)
{
	bool valid;

#if defined(HKDS_KECCAK_HALF_ROUNDS)
	valid = true;
#else
	valid = hkds_selftest_symmetric_run();
#endif

	if (valid == true)
	{
		print_title();

#if !defined(HKDS_KECCAK_HALF_ROUNDS)
		hkdstest_print_line("HKDS: Passed the internal symmetric primitive self-checks.");
#endif

#if defined(HKDS_IS_X86)
		hkdstest_print_line("The system is running in X86 mode; for best performance, compile as X64.");
#endif

#if defined(_DEBUG)
		hkdstest_print_line("The system is running in Debug mode; for best performance, compile as Release.");
#endif

		hkdstest_print_line("");
		hkdstest_print_line("AVX-512 intrinsics have been fully integrated into this project.");
		hkdstest_print_line("On an AVX-512 capable CPU, enable AVX-512 in the project properties for best performance.");
		hkdstest_print_line("Enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
		hkdstest_print_line("\n");

#if defined(HKDS_KECCAK_HALF_ROUNDS)
		hkdstest_print_line("Running in high-performance mode, the HKDS_KECCAK_HALF_ROUNDS is enabled.");
		hkdstest_print_line("Remove the define in hkds_config.h to test operations and standard performance profile.");
#else
		hkdstest_print_line("*** Run the HKDS operational tests; KAT, monte carlo, and stress tests ***");

		if (hkdstest_test_confirm("Press 'Y' and enter to run operation tests, any other key to cancel: ") == true)
		{
			hkdstest_test_run();
		}
#endif

		hkdstest_print_line("");
		hkdstest_print_line("*** Run the HKDS performance benchmarking tests ***");

		if (hkdstest_test_confirm("Press 'Y' and enter to run benchmarking tests, any other key to cancel: ") == true)
		{
			hkdstest_benchmark_hkds_server_run();
			hkdstest_print_line("");
			hkdstest_benchmark_hkds_client_run();
			hkdstest_print_line("");
			hkdstest_benchmark_kmac_run();
			hkdstest_print_line("");
			hkdstest_benchmark_shake_run();
			hkdstest_print_line("");
		}

		hkdstest_print_line("");
		hkdstest_print_line("*** Tests complete, press any key to close ***");
		hkdstest_get_wait();
	}
	else
	{
		hkdstest_print_line("Failure! Internal self-checks have thrown an error, aborting tests!");
		hkdstest_print_line("*** Test failure, press any key to close ***");
		hkdstest_get_wait();
	}

	return 0;
}
