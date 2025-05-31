/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef HKDS_MESSAGE_QUEUE_H
#define HKDS_MESSAGE_QUEUE_H

#include "common.h"
#include "hkds_config.h"

/** 
 * \file hkds_queue.h
 * \brief This file contains the HKDS queue definitions.
 *
 * \details
 * This header defines the constants, structures, and function prototypes for managing the HKDS
 * message queue. The queue is used to store, manage, and export messages within the HKDS system.
 * It provides functionality for initializing the queue, adding and removing items, checking the queue
 * status, and exporting blocks or streams of messages.
 */

/*!
 * \def HKDS_MESSAGE_QUEUE_TAG_SIZE
 * \brief The recommended queue tag size.
 */
#define HKDS_MESSAGE_QUEUE_TAG_SIZE 16U

/*!
 * \def HKDS_QUEUE_ALIGNMENT
 * \brief The internal memory alignment constant.
 */
#define HKDS_QUEUE_ALIGNMENT 64U

/*!
 * \def HKDS_QUEUE_MAX_DEPTH
 * \brief The maximum queue depth.
 */
#define HKDS_QUEUE_MAX_DEPTH 64U

/*!
 * \struct hkds_queue_state
 * \brief Contains the queue context state.
 *
 * \details
 * This structure holds the internal state of a generic HKDS queue, including:
 * - A pointer to a 2-dimensional array representing the queue.
 * - A corresponding array of 64-bit tags for each queue item.
 * - Counters for the current item count, maximum depth, next empty slot (position), and the
 *   maximum byte length (width) of a queue item.
 */
HKDS_EXPORT_API typedef struct hkds_queue_state
{
    uint8_t** queue;                   /*!< Pointer to a 2-dimensional queue array. */
    uint64_t tags[HKDS_QUEUE_MAX_DEPTH]; /*!< 64-bit tag associated with each queue item. */
    size_t count;                      /*!< The number of queue items currently in the queue. */
    size_t depth;                      /*!< The maximum number of items in the queue. */
    size_t position;                   /*!< The index of the next empty slot in the queue. */
    size_t width;                      /*!< The maximum byte length of a queue item. */
} hkds_queue_state;

/*!
 * \struct hkds_message_queue_state
 * \brief Contains the HKDS message queue context state.
 *
 * \details
 * This structure wraps the generic queue state with an associated tag that identifies the message queue.
 */
typedef struct hkds_message_queue_state
{
    uint8_t* tag;           /*!< The tag associated with this message queue. */
    hkds_queue_state state; /*!< The internal queue state context. */
} hkds_message_queue_state;

/**
 * \brief Resets the queue context state.
 *
 * \details
 * This function destroys the message queue context by clearing and freeing all allocated memory,
 * resetting internal counters, and clearing associated tags.
 *
 * \param ctx [in,out] The message queue state context.
 */
HKDS_EXPORT_API void hkds_message_queue_destroy(hkds_message_queue_state* ctx);

/**
 * \brief Flushes the contents of the queue to a byte array.
 *
 * \details
 * This function copies all items currently in the queue to the provided output array, then clears
 * the queue and resets its state.
 *
 * \param ctx [in,out] The message queue state context.
 * \param output [out] The byte array that will receive the flushed queue items.
 */
HKDS_EXPORT_API void hkds_message_queue_flush(hkds_message_queue_state* ctx, uint8_t* output);

/**
 * \brief Initializes the queue state context.
 *
 * \details
 * This function allocates and initializes the internal structures of the message queue with the specified
 * depth, width, and associated tag.
 *
 * \param ctx [in,out] The message queue state context.
 * \param depth [in] The maximum number of items the queue can hold.
 * \param width [in] The maximum byte length of each queue item.
 * \param tag [in] Pointer to the tag associated with the message queue.
 */
HKDS_EXPORT_API void hkds_message_queue_initialize(hkds_message_queue_state* ctx, size_t depth, size_t width, uint8_t* tag);

/**
 * \brief Removes an item from the queue and copies it to the output array.
 *
 * \details
 * This function removes the first item from the queue, copies its data to the provided output array,
 * and shifts the remaining items forward in the queue.
 *
 * \param ctx [in,out] The message queue state context.
 * \param output [out] The output array where the removed item will be stored.
 * \param outlen [in] The length (in bytes) of the output array.
 */
HKDS_EXPORT_API void hkds_message_queue_pop(hkds_message_queue_state* ctx, uint8_t* output, size_t outlen);

/**
 * \brief Adds an item to the queue.
 *
 * \details
 * This function adds a new item to the message queue if space is available.
 *
 * \param ctx [in,out] The message queue state context.
 * \param inpput [in] The input array containing the data to be added.
 * \param inplen [in] The length (in bytes) of the input data.
 */
HKDS_EXPORT_API void hkds_message_queue_push(hkds_message_queue_state* ctx, const uint8_t* inpput, size_t inplen);

/**
 * \brief Checks if the queue is full.
 *
 * \details
 * Returns \c true if the number of items in the queue has reached the maximum depth.
 *
 * \param ctx [in] The message queue state context.
 * \return \c true if the queue is full; otherwise, \c false.
 */
HKDS_EXPORT_API bool hkds_message_queue_full(const hkds_message_queue_state* ctx);

/**
 * \brief Checks if the queue is empty.
 *
 * \details
 * Returns \c true if there are no items in the queue.
 *
 * \param ctx [in] The message queue state context.
 * \return \c true if the queue is empty; otherwise, \c false.
 */
HKDS_EXPORT_API bool hkds_message_queue_empty(const hkds_message_queue_state* ctx);

/**
 * \brief Returns the number of items in the queue.
 *
 * \details
 * Retrieves the current count of items stored in the message queue.
 *
 * \param ctx [in] The message queue state context.
 * \return The number of items currently in the queue.
 */
HKDS_EXPORT_API size_t hkds_message_queue_count(const hkds_message_queue_state* ctx);

/* block message export */

/**
 * \brief Exports a block of 8 messages to a 2-dimensional message queue.
 *
 * \details
 * This function extracts a block of 8 messages from the queue and stores them in a 2D array.
 * The output array should have dimensions [HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE].
 *
 * \param ctx [in,out] The message queue state context.
 * \param output [out] A 2-dimensional array that will receive the exported messages.
 * \return The number of messages exported.
 */
HKDS_EXPORT_API size_t hkds_message_queue_extract_block_x8(hkds_message_queue_state* ctx, uint8_t output[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
 * \brief Exports 8 slots (8 blocks of messages) to a 3-dimensional message queue.
 *
 * \details
 * This function extracts messages from the queue and arranges them in a 3D array with dimensions
 * [HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE].
 *
 * \param ctx [in,out] The message queue state context.
 * \param output [out] A 3-dimensional array that will receive the exported messages.
 * \return The total number of messages exported.
 */
HKDS_EXPORT_API size_t hkds_message_queue_extract_block_x64(hkds_message_queue_state* ctx, uint8_t output[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
 * \brief Serializes a set of messages from the queue to a linear array.
 *
 * \details
 * This function extracts a specified number of messages from the queue and serializes them into a linear byte array.
 *
 * \param ctx [in,out] The message queue state context.
 * \param stream [out] The array that will receive the serialized messages.
 * \param items [in] The number of messages to export.
 * \return The number of messages exported.
 */
HKDS_EXPORT_API size_t hkds_message_queue_extract_stream(hkds_message_queue_state* ctx, uint8_t* stream, size_t items);

#endif
