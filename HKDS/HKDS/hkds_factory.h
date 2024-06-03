
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

#ifndef HKDS_FACTORY_H
#define HKDS_FACTORY_H

#include "common.h"
#include "hkds_config.h"

/* convert header to serialized packet */

/**
* \brief Serialize a packet header to a byte array
*
* \param output [array] The serialized packet header
* \param header [struct][const] The packet header structure
*/
HKDS_EXPORT_API void hkds_factory_serialize_packet_header(uint8_t* output, const hkds_packet_header* header);

/**
* \brief Serialize a client message request to a byte array
*
* \param output [array] The serialized client message request header
* \param header [struct][const] The client message request structure
*/
HKDS_EXPORT_API void hkds_factory_serialize_client_message(uint8_t* output, const hkds_client_message_request* header);

/**
* \brief Serialize a client token request to a byte array
*
* \param output [array] The serialized client token request header
* \param header [struct][const] The client token request structure
*/
HKDS_EXPORT_API void hkds_factory_serialize_client_token(uint8_t* output, const hkds_client_token_request* header);

/**
* \brief Serialize a server message response to a byte array
*
* \param output [array] The server message response request header
* \param header [struct][const] The server message response structure
*/
HKDS_EXPORT_API void hkds_factory_serialize_server_message(uint8_t* output, const hkds_server_message_response* header);

/**
* \brief Serialize a server token response to a byte array
*
* \param output [array] The server token response request header
* \param header [struct][const] The server token response structure
*/
HKDS_EXPORT_API void hkds_factory_serialize_server_token(uint8_t* output, const hkds_server_token_response* header);

/**
* \brief Serialize an administrative message to a byte array
*
* \param output [array] The administrative message request header
* \param header [struct][const] The administrative message structure
*/
HKDS_EXPORT_API void hkds_factory_serialize_administrative_message(uint8_t* output, const hkds_administrative_message* header);

/**
* \brief Serialize an error message to a byte array
*
* \param output [array] The error message request header
* \param header [struct][const] The error message structure
*/
HKDS_EXPORT_API void hkds_factory_serialize_error_message(uint8_t* output, const hkds_error_message* header);

/* convert serialized packet to header */

/**
* \brief Extract a packet header structure from a byte array
*
* \param input [array][const] The serialized packet input array
* \return An hkds packet header structure
*/
HKDS_EXPORT_API hkds_packet_header hkds_factory_extract_packet_header(const uint8_t* input);

/**
* \brief Extract a client message request from a byte array
*
* \param input [array][const] The serialized client message request input array
* \return [struct] A client message request structure
*/
HKDS_EXPORT_API hkds_client_message_request hkds_factory_extract_client_message(const uint8_t* input);

/**
* \brief Extract a client token request from a byte array
*
* \param input [array][const] The serialized client token request input array
* \return [struct] A client message token structure
*/
HKDS_EXPORT_API hkds_client_token_request hkds_factory_extract_client_token(const uint8_t* input);

/**
* \brief Extract a server message response from a byte array
*
* \param input [array][const] The serialized server message response input array
* \return [struct] A server message response structure
*/
HKDS_EXPORT_API hkds_server_message_response hkds_factory_extract_server_message(const uint8_t* input);

/**
* \brief Extract a server token response from a byte array
*
* \param input [array][const] The serialized server token response input array
* \return [struct] A server token response structure
*/
HKDS_EXPORT_API hkds_server_token_response hkds_factory_extract_server_token(const uint8_t* input);

/**
* \brief Extract an administrative message from a byte array
*
* \param input [array][const] The serialized administrative message input array
* \return [struct] An administrative message structure
*/
HKDS_EXPORT_API hkds_administrative_message hkds_factory_extract_administrative_message(const uint8_t* input);

/**
* \brief Extract an error message from a byte array
*
* \param input [array][const] The serialized error message input array
* \return [struct] An error message structure
*/
HKDS_EXPORT_API hkds_error_message hkds_factory_extract_error_message(const uint8_t* input);

/* packet construction */

/**
* \brief Build a client message request from components
*
* \param message [array][const] The encrypted client message array
* \param ksn [array][const] The clients KSN array
* \param tag [array][const] The [optional] authentication tag
* \return [struct] A client message request structure
*/
HKDS_EXPORT_API hkds_client_message_request hkds_factory_create_client_message_request(const uint8_t* message, const uint8_t* ksn, const uint8_t* tag);

/**
* \brief Build a client token request from components
*
* \param ksn [array][const] The clients KSN array
* \return [struct] A client token request structure
*/
HKDS_EXPORT_API hkds_client_token_request hkds_factory_create_client_token_request(const uint8_t* ksn);

/**
* \brief Build a server message response from components
*
* \param message [array][const] The server message response array
* \return [struct] A server message response structure
*/
HKDS_EXPORT_API hkds_server_message_response hkds_factory_create_server_message_response(const uint8_t* message);

/**
* \brief Build a server token response from components
*
* \param etok [array][const] The servers encrypted token response array
* \return [struct] A server token response structure
*/
HKDS_EXPORT_API hkds_server_token_response hkds_factory_create_server_token_reponse(const uint8_t* etok);

/**
* \brief Build an administrative message from components
*
* \param message [array][const] The administrative message array
* \return [struct] An administrative message structure
*/
HKDS_EXPORT_API hkds_administrative_message hkds_factory_create_administrative_message(const uint8_t* message);

/**
* \brief Build an error message from components
*
* \param message [array][const] The error message array
* \return [struct] An error message structure
*/
HKDS_EXPORT_API hkds_error_message hkds_factory_create_error_message(const uint8_t* message, hkds_error_type err);

/* raw packet value extraction  */

/**
* \brief Extract the packet type enumeral from a serialized packet header
*
* \param input [array][const] The serialized packet header array
* \return [enumeration] The packet type numeral
*/
HKDS_EXPORT_API hkds_packet_type hkds_factory_extract_packet_type(const uint8_t* input);

/**
* \brief Extract the protocol id numeral from a serialized packet header
*
* \param input [array][const] The serialized packet header array
* \return [enumeration] The protocol id numeral
*/
HKDS_EXPORT_API hkds_protocol_id hkds_factory_extract_protocol_id(const uint8_t* input);

/**
* \brief Extract the packet size from a serialized packet header
*
* \param input [array][const] The serialized packet header array
* \return [size] The packet size, including the header and payload
*/
HKDS_EXPORT_API size_t hkds_factory_extract_packet_size(const uint8_t* input);

/**
* \brief Extract the packet sequence from a serialized packet header
*
* \param input [array][const] The serialized packet header array
* \return [size] The packet sequence number
*/
HKDS_EXPORT_API uint8_t hkds_factory_extract_packet_sequence(const uint8_t* input);

#endif
