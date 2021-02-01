/* 2020 Digital Freedom Defense Incorporated
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Digital Freedom Defense Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Digital Freedom Defense Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Digital Freedom Defense Incorporated.
 *
 * Written by John G. Underhill
 * Written on March 29, 2020
 * Updated on November 24, 2020
 * Contact: develop@dfdef.com
 */

#ifndef HKDS_SELFTEST_H
#define HKDS_SELFTEST_H

#include "common.h"

/**
* \brief Tests the SHA3 digests, SHAKE, cSHAKE, and KMAC for correct operation.
*
* \return Returns true for success
*/
HKDS_EXPORT_API bool hkdstest_sha3_test();

/**
* \brief Runs the library self tests.
* Tests the symmetric primitives with a set of known-answer tests.
*
* \return Returns true if all tests pass successfully
*/
HKDS_EXPORT_API bool hkdstest_symmetric_selftest_run();

#endif