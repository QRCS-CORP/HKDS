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
* Written by John G. Underhill
* Updated on November 11, 2020
* Contact: develop@vtdev.com */

#ifndef QSC_EVENT_H
#define QSC_EVENT_H

#include "common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define QSC_EVENT_LIST_LENGTH 4

typedef enum qsc_event_list
{
	qsc_event_receive_callback = 0,
	qsc_event_send_callback = 1,
	qsc_event_connection_request = 3,
	qsc_event_connection_shutdown = 4
} qsc_event_list;

typedef void (*qsc_event_callback)(void*);

QSC_EXPORT_API typedef struct qsc_event_handlers
{
	qsc_event_callback cb;
	struct EventHandlers *next;
} qsc_event_handlers;

qsc_event_handlers* listeners[QSC_EVENT_LIST_LENGTH];

QSC_EXPORT_API int32_t qsc_event_register(qsc_event_list event, qsc_event_callback cb)
{
	qsc_event_handlers *handlers = listeners[event];

	if (handlers == NULL)
	{
		if (!(handlers = (qsc_event_handlers*)malloc(sizeof(qsc_event_handlers))))
		{
			return 0; // error returned from malloc
		}

		handlers->cb = cb;
		handlers->next = NULL;
		listeners[event] = handlers;
	}
	else
	{
		while (handlers->next != NULL) 
		{
			// handlers already registered for this event
			// check to see if it is a redundant handler for this event
			handlers = handlers->next;

			if (handlers->cb == cb)
			{
				return -1;
			}
		}

		qsc_event_handlers *nextHandler;

		if (!(nextHandler = (qsc_event_handlers*)malloc(sizeof(qsc_event_handlers))))
		{
			return 0; // error returned from malloc
		}

		nextHandler->cb = cb;
		nextHandler->next = NULL;
		handlers->next = nextHandler;
	}

	return 1;
}

QSC_EXPORT_API void qsc_event_init_listeners(qsc_event_handlers* handlers[], size_t size)
{
	size_t i;

	for (i = 0; i < QSC_EVENT_LIST_LENGTH; ++i)
	{
		handlers[i] = NULL;
	}
}

QSC_EXPORT_API void qsc_event_destroy_listeners(qsc_event_handlers* handlers[], int size)
{
	size_t i;
	qsc_event_handlers* dh;
	qsc_event_handlers* next;

	for (i = 0; i < QSC_EVENT_LIST_LENGTH; i++)
	{
		dh = handlers[i];

		while (dh)
		{
			next = dh->next;
			free(dh);
			dh = next;
		}
	}
}

#endif