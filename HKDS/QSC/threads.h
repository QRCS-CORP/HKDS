/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* A threading base class.
* Written by John G. Underhill
* Updated on December 30, 2020
* Contact: develop@vtdev.com */

#ifndef QSC_THREADS_H
#define QSC_THREADS_H

#include "common.h"
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <process.h>
#	include <Windows.h>
#elif defined(QSC_SYSTEM_OS_POSIX)
#	include <sys/types.h>
#	include <unistd.h>
#	include <pthread>
#else
#	error your operating system is not supported!
#endif

#if !defined(pthread_t)
#	define pthread_t int
#endif

QSC_EXPORT_API pthread_t qsc_threads_initialize(void (*thd_func)(void*), void* state)
{
	pthread_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _beginthread(thd_func, 0, state);
#elif defined(QSC_SYSTEM_OS_POSIX)
	p_thread_create(&res, NULL, thd_func, state);
#endif

	return res;
}

QSC_EXPORT_API void qsc_threads_terminate(pthread_t instance)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	_endthread(instance);
#elif defined(QSC_SYSTEM_OS_POSIX)
	pthread_cancel(instance);
#endif

	memset(instance, 0x00, sizeof(instance));
}

#endif
