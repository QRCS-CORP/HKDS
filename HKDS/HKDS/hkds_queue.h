
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

#ifndef HKDS_MESSAGE_QUEUE_H
#define HKDS_MESSAGE_QUEUE_H

#include "common.h"
#include "hkds_config.h"

 /*!
 \def HKDS_MESSAGE_QUEUE_TAG_SIZE
 * The recommended queue tag size
 */
#define HKDS_MESSAGE_QUEUE_TAG_SIZE 16

/*!
\def HKDS_QUEUE_ALIGNMENT
* The internal memory alignment constant
*/
#define HKDS_QUEUE_ALIGNMENT 64

/*!
\def HKDS_QUEUE_MAX_DEPTH
* The maximum queue depth
*/
#define HKDS_QUEUE_MAX_DEPTH 64

/*! \struct hkds_queue_state
* Contains the queue context state
*/
HKDS_EXPORT_API typedef struct hkds_queue_state
{
	uint8_t** queue;					/*!< The pointer to a 2 dimensional queue array */
	uint64_t tags[HKDS_QUEUE_MAX_DEPTH];	/*!< The 64-bit tag associated with each queue item  */
	size_t count;						/*!< The number of queue items */
	size_t depth;						/*!< The maximum number of items in the queue */
	size_t position;					/*!< The next empty slot in the queue */
	size_t width;						/*!< The maximum byte length of a queue item */
} hkds_queue_state;

 /* packet queueing */


/*! \struct hkds_message_queue_state
* Contains the hkds queue context state
*/
typedef struct hkds_message_queue_state
{
	uint8_t* tag;			/*!< The tag associated with this queue */
	hkds_queue_state state;	/*!< The queue state context */
} hkds_message_queue_state;

/**
* \brief Resets the queue context state
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_message_queue_destroy(hkds_message_queue_state* ctx);

/**
* \brief Flush the contents of the queue to a byte array
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_message_queue_flush(hkds_message_queue_state* ctx, uint8_t* output);

/**
* \brief Initializes the queues state context
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_message_queue_initialize(hkds_message_queue_state* ctx, size_t depth, size_t width, uint8_t* tag);

/**
* \brief Removes an item from the queue and copies it to the output array
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_message_queue_pop(hkds_message_queue_state* ctx, uint8_t* output, size_t outlen);

/**
* \brief Adds an item from the queue
*
* \param ctx [struct] The message queue state context
*/
HKDS_EXPORT_API void hkds_message_queue_push(hkds_message_queue_state* ctx, const uint8_t* inpput, size_t inplen);

/**
* \brief Returns true if the queue is full
*
* \param ctx [struct] The message queue state context
* \return [bool] The queue full status
*/
HKDS_EXPORT_API bool hkds_message_queue_full(const hkds_message_queue_state* ctx);

/**
* \brief Returns true if the queue is empty
*
* \param ctx [struct] The message queue state context
* \return [bool] The queue empty status
*/
HKDS_EXPORT_API bool hkds_message_queue_empty(const hkds_message_queue_state* ctx);

/**
* \brief Returns the number of items in the queue
*
* \param ctx [struct] The message queue state context
* \return [size] The number of items
*/
HKDS_EXPORT_API size_t hkds_message_queue_count(const hkds_message_queue_state* ctx);

/* block message export */

/**
* \brief Export a block of 8 messages to a 2-dimensional message queue
*
* \param ctx [struct] The message queue state context
* \param output [array2d] The 2d array receiving the messages; containing HKDS_CACHX8_DEPTH of items of array HKDS_MESSAGE_SIZE length
* \return [size] The number of items exported
*/
HKDS_EXPORT_API size_t hkds_message_queue_extract_block_x8(hkds_message_queue_state* ctx, uint8_t output[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
* \brief Export 8 slots 8 blocks of messages (8x8) to a 3-dimensional message queue
*
* \param ctx [struct] The message queue state context
* \param output [array3d] The 3d array receiving the messages; HKDS_PARALLEL_DEPTH slots, containing HKDS_CACHX64_DEPTH of items of array HKDS_MESSAGE_SIZE length
* \return [size] The number of items exported
*/
HKDS_EXPORT_API size_t hkds_message_queue_extract_block_x64(hkds_message_queue_state* ctx, uint8_t output[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
* \brief Serialize a set of messages to an array
*
* \param ctx [struct] The message queue state context
* \param stream [array] The array receiving the messages
* \return [size] The number of items exported
*/
HKDS_EXPORT_API size_t hkds_message_queue_extract_stream(hkds_message_queue_state* ctx, uint8_t* stream, size_t items);

#endif
