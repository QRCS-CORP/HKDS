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

#ifndef HKDSTEST_TIMER_H
#define HKDSTEST_TIMER_H

#include "common.h"
#include <time.h>

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
clock_t hkdstest_timer_start();

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The timke difference in milliseconds
*/
uint64_t hkdstest_timer_elapsed(clock_t start);

#endif