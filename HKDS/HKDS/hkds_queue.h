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
 * Written on November 20, 2020
 * Updated on December 9, 2021
 * Contact: develop@dfdef.com
 */

#ifndef HKDS_QUEUE_H
#define HKDS_QUEUE_H

#include "common.h"
#include "hkds_config.h"
#include "../QSC/queue.h"

 /*!
 \def HKDS_QUEUETAG_SIZE
 * The recommended queue tag size
 */
#define HKDS_QUEUETAG_SIZE 16

 /* packet queueing */


/*! \struct hkds_queue_message_queue
* Contains the hkds queue context state
*/
typedef struct hkds_queue_message_queue
{
	uint8_t* tag;			/*!< The tag associated with this queue */
	qsc_queue_state state;	/*!< The queue state context */
}
hkds_queue_message_queue;

/**
* \brief Resets the queue context state
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_queue_destroy(hkds_queue_message_queue* ctx);

/**
* \brief Flush the contents of the queue to a byte array
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_queue_flush(hkds_queue_message_queue* ctx, uint8_t* output);

/**
* \brief Initializes the queues state context
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_queue_initialize(hkds_queue_message_queue* ctx, size_t depth, size_t width, uint8_t* tag);

/**
* \brief Removes an item from the queue and copies it to the output array
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_queue_pop(hkds_queue_message_queue* ctx, uint8_t* output, size_t outlen);

/**
* \brief Adds an item from the queue
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_queue_push(hkds_queue_message_queue* ctx, const uint8_t* output, size_t outlen);

/**
* \brief Returns true if the queue is full
*
* \param ctx [struct] The message queue state context
* \return [bool] The queue full status
*/
HKDS_EXPORT_API bool hkds_queue_isfull(const hkds_queue_message_queue* ctx);

/**
* \brief Returns true if the queue is empty
*
* \param ctx [struct] The message queue state context
* \return [bool] The queue empty status
*/
HKDS_EXPORT_API bool hkds_queue_isempty(const hkds_queue_message_queue* ctx);

/**
* \brief Returns the number of items in the queue
*
* \param ctx [struct] The message queue state context
* \return [size] The number of items
*/
HKDS_EXPORT_API size_t hkds_queue_count(const hkds_queue_message_queue* ctx);

/* block message export */

/**
* \brief Export a block of 8 messages to a 2-dimensional message queue
*
* \param ctx [struct] The message queue state context
* \param output [array2d] The 2d array receiving the messages; containing HKDS_CACHX8_DEPTH of items of array HKDS_MESSAGE_SIZE length
* \return [size] The number of items exported
*/
HKDS_EXPORT_API size_t hkds_queue_extract_block_x8(hkds_queue_message_queue* ctx, uint8_t output[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
* \brief Export 8 slots 8 blocks of messages (8x8) to a 3-dimensional message queue
*
* \param ctx [struct] The message queue state context
* \param output [array3d] The 3d array receiving the messages; HKDS_PARALLEL_DEPTH slots, containing HKDS_CACHX64_DEPTH of items of array HKDS_MESSAGE_SIZE length
* \return [size] The number of items exported
*/
HKDS_EXPORT_API size_t hkds_queue_extract_block_x64(hkds_queue_message_queue* ctx, uint8_t output[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
* \brief Serialize a set of messages to an array
*
* \param ctx [struct] The message queue state context
* \param stream [array] The array receiving the messages
* \return [size] The number of items exported
*/
HKDS_EXPORT_API size_t hkds_queue_extract_stream(hkds_queue_message_queue* ctx, uint8_t* stream, size_t items);

#endif
