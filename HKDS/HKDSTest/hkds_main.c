/* 2024 Quantum Resistant Cryptographic Solutions Corporation
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
 * Updated on May 30, 2024
 * Contact: develop@qrcs.ca
 */

#include "hkds_benchmark.h"
#include "hkds_test.h"
#include "testutils.h"
#include "../HKDS/common.h"
#include "../HKDS/utils.h"
#include "../HKDS/hkds_config.h"
#include "../HKDS/hkds_selftest.h"
#include <stdlib.h>
#include <stdio.h>


void print_title(void)
{
	qsctest_print_line("******************************************************");
	qsctest_print_line("* HKDS: Heirarchal symmetric Key Distribution System *");
	qsctest_print_line("*                                                    *");
	qsctest_print_line("* Release:   v1.0.0.2 (A2)                           *");
	qsctest_print_line("* License:   Copyrighted and Patent pending          *");
	qsctest_print_line("* Date:      May 30 2024                             *");
	qsctest_print_line("* Author:    John G. Underhill                       *");
	qsctest_print_line("* Contact:   develop@qrcs.ca                         *");
	qsctest_print_line("******************************************************");
	qsctest_print_line("");
}

int main(void)
{
	utils_cpu_features cfeat;
	bool valid;
	bool res;

#if defined(HKDS_KECCAK_HALF_ROUNDS)
	valid = true;
#else
	valid = hkds_selftest_symmetric_run();
#endif

	if (valid == true)
	{
		print_title();

#if !defined(HKDS_KECCAK_HALF_ROUNDS)
		qsctest_print_line("HKDS: Passed the internal symmetric primitive self-checks.");
#endif

		res = utils_cpu_features_set(&cfeat);

		if (res == false)
		{
			qsctest_print_line("The CPU type was not recognized on this system!");
			qsctest_print_line("Some features may be disabled.");
		}

		if (cfeat.avx512f == true)
		{
			qsctest_print_line("AVX-512 intrinsics functions have been detected on this system.");
		}
		else if (cfeat.avx2 == true)
		{
			qsctest_print_line("AVX2 intrinsics functions have been detected on this system.");
		}
		else if (cfeat.avx == true)
		{
			qsctest_print_line("AVX intrinsics functions have been detected on this system.");
		}
		else
		{
			qsctest_print_line("The AVX intrinsics functions have not been detected or are not enabled.");
			qsctest_print_line("For best performance, enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
		}

#if defined(HKDS_IS_X86)
		qsctest_print_line("The system is running in X86 mode; for best performance, compile as X64.");
#endif

#if defined(_DEBUG)
		qsctest_print_line("The system is running in Debug mode; for best performance, compile as Release.");
#endif

		qsctest_print_line("");
		qsctest_print_line("AVX-512 intrinsics have been fully integrated into this project.");
		qsctest_print_line("On an AVX-512 capable CPU, enable AVX-512 in the project properties for best performance.");
		qsctest_print_line("Enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
		qsctest_print_line("\n");

#if defined(HKDS_KECCAK_HALF_ROUNDS)
		qsctest_print_line("Running in high-performance mode, the HKDS_KECCAK_HALF_ROUNDS is enabled.");
		qsctest_print_line("Remove the define in hkds_config.h to test operations and standard performance profile.");
#else
		qsctest_print_line("*** Run the HKDS operational tests; KAT, monte carlo, and stress tests ***");

		if (qsctest_test_confirm("Press 'Y' and enter to run operation tests, any other key to cancel: ") == true)
		{
			hkdstest_test_run();
		}
#endif

		qsctest_print_line("");
		qsctest_print_line("*** Run the HKDS performance benchmarking tests ***");

		if (qsctest_test_confirm("Press 'Y' and enter to run benchmarking tests, any other key to cancel: ") == true)
		{
			hkdstest_benchmark_hkds_server_run();
			qsctest_print_line("");
			hkdstest_benchmark_hkds_client_run();
			qsctest_print_line("");
			hkdstest_benchmark_kmac_run();
			qsctest_print_line("");
			hkdstest_benchmark_shake_run();
			qsctest_print_line("");
		}

		qsctest_print_line("");
		qsctest_print_line("*** Tests complete, press any key to close ***");
		qsctest_get_wait();
	}
	else
	{
		qsctest_print_line("Failure! Internal self-checks have thrown an error, aborting tests!");
		qsctest_print_line("*** Test failure, press any key to close ***");
		qsctest_get_wait();
	}

	return 0;
}
