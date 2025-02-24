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

#ifndef HKDS_FACTORY_H
#define HKDS_FACTORY_H

#include "common.h"
#include "hkds_config.h"

/**
 * \file hkds_factory.h
 * \brief This file contains the HKDS factory definitions.
 *
 * \details
 * This file provides functions to serialize and deserialize HKDS packet structures to and from
 * raw byte arrays, and functions to construct HKDS packet structures from individual components.
 * The functions support:
 *  - Serialization of packet headers and complete packets (client message, client token, server message,
 *    server token, administrative, and error messages) for network transmission.
 *  - Extraction of packet structures and header fields from serialized byte arrays.
 *  - Construction of packet structures by combining individual components.
 */

/* convert header to serialized packet */

/**
 * \brief Serialize a packet header to a byte array.
 *
 * \param output [out] The serialized packet header.
 * \param header [in] The packet header structure.
 */
HKDS_EXPORT_API void hkds_factory_serialize_packet_header(uint8_t* output, const hkds_packet_header* header);

/**
 * \brief Serialize a client message request to a byte array.
 *
 * \param output [out] The serialized client message request header.
 * \param header [in] The client message request structure.
 */
HKDS_EXPORT_API void hkds_factory_serialize_client_message(uint8_t* output, const hkds_client_message_request* header);

/**
 * \brief Serialize a client token request to a byte array.
 *
 * \param output [out] The serialized client token request header.
 * \param header [in] The client token request structure.
 */
HKDS_EXPORT_API void hkds_factory_serialize_client_token(uint8_t* output, const hkds_client_token_request* header);

/**
 * \brief Serialize a server message response to a byte array.
 *
 * \param output [out] The serialized server message response header.
 * \param header [in] The server message response structure.
 */
HKDS_EXPORT_API void hkds_factory_serialize_server_message(uint8_t* output, const hkds_server_message_response* header);

/**
 * \brief Serialize a server token response to a byte array.
 *
 * \param output [out] The serialized server token response header.
 * \param header [in] The server token response structure.
 */
HKDS_EXPORT_API void hkds_factory_serialize_server_token(uint8_t* output, const hkds_server_token_response* header);

/**
 * \brief Serialize an administrative message to a byte array.
 *
 * \param output [out] The serialized administrative message header.
 * \param header [in] The administrative message structure.
 */
HKDS_EXPORT_API void hkds_factory_serialize_administrative_message(uint8_t* output, const hkds_administrative_message* header);

/**
 * \brief Serialize an error message to a byte array.
 *
 * \param output [out] The serialized error message header.
 * \param header [in] The error message structure.
 */
HKDS_EXPORT_API void hkds_factory_serialize_error_message(uint8_t* output, const hkds_error_message* header);

/* convert serialized packet to header */

/**
 * \brief Extract a packet header structure from a byte array.
 *
 * \param input [in] The serialized packet input array.
 * \return An hkds packet header structure.
 */
HKDS_EXPORT_API hkds_packet_header hkds_factory_extract_packet_header(const uint8_t* input);

/**
 * \brief Extract a client message request from a byte array.
 *
 * \param input [in] The serialized client message request input array.
 * \return A client message request structure.
 */
HKDS_EXPORT_API hkds_client_message_request hkds_factory_extract_client_message(const uint8_t* input);

/**
 * \brief Extract a client token request from a byte array.
 *
 * \param input [in] The serialized client token request input array.
 * \return A client token request structure.
 */
HKDS_EXPORT_API hkds_client_token_request hkds_factory_extract_client_token(const uint8_t* input);

/**
 * \brief Extract a server message response from a byte array.
 *
 * \param input [in] The serialized server message response input array.
 * \return A server message response structure.
 */
HKDS_EXPORT_API hkds_server_message_response hkds_factory_extract_server_message(const uint8_t* input);

/**
 * \brief Extract a server token response from a byte array.
 *
 * \param input [in] The serialized server token response input array.
 * \return A server token response structure.
 */
HKDS_EXPORT_API hkds_server_token_response hkds_factory_extract_server_token(const uint8_t* input);

/**
 * \brief Extract an administrative message from a byte array.
 *
 * \param input [in] The serialized administrative message input array.
 * \return An administrative message structure.
 */
HKDS_EXPORT_API hkds_administrative_message hkds_factory_extract_administrative_message(const uint8_t* input);

/**
 * \brief Extract an error message from a byte array.
 *
 * \param input [in] The serialized error message input array.
 * \return An error message structure.
 */
HKDS_EXPORT_API hkds_error_message hkds_factory_extract_error_message(const uint8_t* input);

/* packet construction */

/**
 * \brief Build a client message request from components.
 *
 * \param message [in] The encrypted client message array.
 * \param ksn [in] The client's KSN array.
 * \param tag [in] The [optional] authentication tag.
 * \return A client message request structure.
 */
HKDS_EXPORT_API hkds_client_message_request hkds_factory_create_client_message_request(const uint8_t* message, const uint8_t* ksn, const uint8_t* tag);

/**
 * \brief Build a client token request from components.
 *
 * \param ksn [in] The client's KSN array.
 * \return A client token request structure.
 */
HKDS_EXPORT_API hkds_client_token_request hkds_factory_create_client_token_request(const uint8_t* ksn);

/**
 * \brief Build a server message response from components.
 *
 * \param message [in] The server message response array.
 * \return A server message response structure.
 */
HKDS_EXPORT_API hkds_server_message_response hkds_factory_create_server_message_response(const uint8_t* message);

/**
 * \brief Build a server token response from components.
 *
 * \param etok [in] The server's encrypted token response array.
 * \return A server token response structure.
 */
HKDS_EXPORT_API hkds_server_token_response hkds_factory_create_server_token_reponse(const uint8_t* etok);

/**
 * \brief Build an administrative message from components.
 *
 * \param message [in] The administrative message array.
 * \return An administrative message structure.
 */
HKDS_EXPORT_API hkds_administrative_message hkds_factory_create_administrative_message(const uint8_t* message);

/**
 * \brief Build an error message from components.
 *
 * \param message [in] The error message array.
 * \param err [in] The error type to be included in the packet header.
 * \return An error message structure.
 */
HKDS_EXPORT_API hkds_error_message hkds_factory_create_error_message(const uint8_t* message, hkds_error_type err);

/* raw packet value extraction  */

/**
 * \brief Extract the packet type enumeral from a serialized packet header.
 *
 * \param input [in] The serialized packet header array.
 * \return The packet type numeral.
 */
HKDS_EXPORT_API hkds_packet_type hkds_factory_extract_packet_type(const uint8_t* input);

/**
 * \brief Extract the protocol id numeral from a serialized packet header.
 *
 * \param input [in] The serialized packet header array.
 * \return The protocol id numeral.
 */
HKDS_EXPORT_API hkds_protocol_id hkds_factory_extract_protocol_id(const uint8_t* input);

/**
 * \brief Extract the packet size from a serialized packet header.
 *
 * \param input [in] The serialized packet header array.
 * \return The packet size, including the header and payload.
 */
HKDS_EXPORT_API size_t hkds_factory_extract_packet_size(const uint8_t* input);

/**
 * \brief Extract the packet sequence from a serialized packet header.
 *
 * \param input [in] The serialized packet header array.
 * \return The packet sequence number.
 */
HKDS_EXPORT_API uint8_t hkds_factory_extract_packet_sequence(const uint8_t* input);

#endif
