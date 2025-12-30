/* 2021-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
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
