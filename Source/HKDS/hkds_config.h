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

#ifndef HKDS_CONFIG_H
#define HKDS_CONFIG_H

#include "common.h"

/**
 * \file hkds_config.h
 * \brief HKDS configuration definitions.
 *
 * \details
 * This header file defines the configuration parameters, enumerations, macros, and structures used by the
 * Hierarchical Key Derivation System (HKDS) protocol. The HKDS protocol leverages cryptographic primitives
 * (such as SHA-3, SHAKE, and KMAC) to securely exchange tokens and messages between client devices and a transaction server.
 *
 * The file is organized as follows:
 *  - Enumerations: Define the packet types, protocol identifiers, error types, and message types used in HKDS communications.
 *  - Modifiable Values: Macros allowing customization of the Keccak round settings, SHAKE implementations, and key cache multiplier.
 *  - Static Values: Fixed-size constants (key sizes, message sizes, identifiers, etc.) required for the HKDS protocol.
 *  - Packet Headers: Structures that describe the layout of the various HKDS message packets.
 *
 * These definitions ensure consistency across the protocol implementation and allow flexibility to adapt the system to
 * different security levels and performance requirements.
 */

/*** Enumerations ***/

/*! \enum hkds_packet_type
 * \brief Enumerates the types of packets used in HKDS communications.
 *
 * \details
 * This enumeration defines the various packet types exchanged between client and server:
 * - \c packet_token_request: A client token request.
 * - \c packet_token_response: A server token response.
 * - \c packet_message_request: A client message request.
 * - \c packet_message_response: A server message response.
 * - \c packet_administrative_message: An administrative message.
 * - \c packet_error_message: An error message.
 */
typedef enum hkds_packet_type
{
    packet_token_request         = 0x01U,    /*!< A client token request */
    packet_token_response        = 0x02U,    /*!< A server token response */
    packet_message_request       = 0x03U,    /*!< A client message request */
    packet_message_response      = 0x04U,    /*!< A server message response */
    packet_administrative_message= 0x05U,    /*!< An administrative message */
    packet_error_message         = 0x06U     /*!< An error message */
} hkds_packet_type;

/*! \enum hkds_protocol_id
 * \brief Enumerates the supported cryptographic protocol identifiers.
 *
 * \details
 * This enumeration specifies which SHAKE variant is employed by the HKDS protocol:
 * - \c protocol_shake_128: Uses SHAKE-128.
 * - \c protocol_shake_256: Uses SHAKE-256.
 * - \c protocol_shake_512: Uses SHAKE-512.
 */
typedef enum hkds_protocol_id
{
    protocol_shake_128 = 0x09U,    /*!< Protocol is SHAKE-128 */
    protocol_shake_256 = 0x0AU,    /*!< Protocol is SHAKE-256 */
    protocol_shake_512 = 0x0BU     /*!< Protocol is SHAKE-512 */
} hkds_protocol_id;

/*! \enum hkds_error_type
 * \brief Enumerates the error types for HKDS packet communications.
 *
 * \details
 * This enumeration defines the error codes that may be communicated in HKDS error messages:
 * - \c error_general_failure: General failure.
 * - \c error_connection_aborted: The connection was aborted by the remote host.
 * - \c error_disconnected: The network link was lost.
 * - \c error_connection_refused: The connection was refused by the remote host.
 * - \c error_invalid_format: The request format was invalid.
 * - \c error_retries_exceeded: The allowed number of retries was exceeded.
 * - \c error_connection_failure: The connection experienced a general failure.
 * - \c error_unkown_failure: The cause of failure is unknown.
 */
typedef enum hkds_error_type
{
    error_general_failure       = 0x1FU,    /*!< General failure */
    error_connection_aborted    = 0x21U,    /*!< The connection was aborted by the remote host */
    error_disconnected          = 0x22U,    /*!< The network link was lost */
    error_connection_refused    = 0x23U,    /*!< The connection was refused by the remote host */
    error_invalid_format        = 0x24U,    /*!< The request format was invalid */
    error_retries_exceeded      = 0x25U,    /*!< The allowed number of retries was exceeded */
    error_connection_failure    = 0x26U,    /*!< The connection had a general failure */
    error_unkown_failure        = 0xFFU     /*!< The cause of failure is unknown */
} hkds_error_type;

/*! \enum hkds_message_type
 * \brief Enumerates the HKDS packet message types.
 *
 * \details
 * This enumeration defines the specific message types sent after token processing:
 * - \c message_synchronize_token: Sent by the client when a token key fails authentication.
 * - \c message_reinitialized_token: The server's (optional) response to a token key rejection.
 * - \c message_token_requests_exceeded: Indicates that the maximum number of token failures has occurred.
 * - \c message_remote_reset: Sent by the server to remotely reset the client terminal.
 * - \c message_diagnostic: Requests diagnostic output from the terminal's hardware components.
 * - \c message_reserved1, \c message_reserved2, \c message_reserved3: Reserved for future use.
 */
typedef enum hkds_message_type
{
    message_synchronize_token      = 0x01U,   /*!< Sent by the client indicating a token key failure */
    message_reinitialized_token    = 0x02U,   /*!< The server's response to a token key rejection */
    message_token_requests_exceeded= 0x03U,   /*!< The server indicates that maximum token failures occurred */
    message_remote_reset           = 0x04U,   /*!< The server sends a remote reset to the client terminal */
    message_diagnostic             = 0x05U,   /*!< The server requests diagnostic output */
    message_reserved1              = 0x06U,   /*!< Reserved message 1 */
    message_reserved2              = 0x07U,   /*!< Reserved message 2 */
    message_reserved3              = 0x08U    /*!< Reserved message 3 */
} hkds_message_type;

/*** Modifiable Values ***/

/*!
 * \def HKDS_KECCAK_DOUBLE_ROUNDS
 * \brief Enable double rounds of Keccak.
 *
 * \details
 * When defined, HKDS will run the Keccak permutation with 48 rounds instead of the standard 24.
 */
//#define HKDS_KECCAK_DOUBLE_ROUNDS

/*!
 * \def HKDS_KECCAK_HALF_ROUNDS
 * \brief Enable half rounds of Keccak.
 *
 * \details
 * When defined, HKDS will run the Keccak permutation with 12 rounds instead of the standard 24.
 */
//#define HKDS_KECCAK_HALF_ROUNDS

/*!
 * \def HKDS_SHAKE_128
 * \brief Use the SHAKE-128 variant for HKDS.
 *
 * \details
 * When defined, the implementation uses SHAKE-128 for cryptographic operations.
 */
//#define HKDS_SHAKE_128

/*!
 * \def HKDS_SHAKE_256
 * \brief Use the SHAKE-256 variant for HKDS.
 *
 * \details
 * When defined, the implementation uses SHAKE-256 for cryptographic operations.
 */
#define HKDS_SHAKE_256

/*!
 * \def HKDS_SHAKE_512
 * \brief Use the SHAKE-512 variant for HKDS.
 *
 * \details
 * When defined, the implementation uses SHAKE-512 for cryptographic operations.
 */
//#define HKDS_SHAKE_512

/*!
 * \def HKDS_CACHE_MULTIPLIER
 * \brief Defines the transaction key cache multiplier.
 *
 * \details
 * Changes the size of the transaction key cache. Allowed values are multiples of 2 (2, 4, 6, 8, 10, and 12).
 * A larger multiplier results in fewer token exchanges, but leads to slower decryption and a larger client cache.
 * The recommended value is 4, and it should not exceed 8.
 */
#define HKDS_CACHE_MULTIPLIER 4U

/*** Static Values (Do Not Change) ***/

/*!
 * \def HKDS_ADMIN_SIZE
 * \brief The size of the administrative message in bytes.
 */
#define HKDS_ADMIN_SIZE 2U

/*!
 * \def HKDS_AUTHENTICATION_KMAC
 * \brief The KMAC authentication mode designator contained in a client's DID.
 */
#define HKDS_AUTHENTICATION_KMAC 0x11U

/*!
 * \def HKDS_AUTHENTICATION_NONE
 * \brief The authentication mode designator for no authentication.
 */
#define HKDS_AUTHENTICATION_NONE 0x10U

/*!
 * \def HKDS_AUTHENTICATION_SHA3
 * \brief The SHA3 authentication mode designator contained in a client's DID.
 */
#define HKDS_AUTHENTICATION_SHA3 0x12U

/*!
 * \def HKDS_PARALLEL_DEPTH
 * \brief The AVX512 depth multiplier.
 *
 * \details
 * Specifies the number of simultaneous server decryption and token generation operations when using the (x8) SIMD API.
 */
#define HKDS_PARALLEL_DEPTH 8U

/*!
 * \def HKDS_CACHX8_DEPTH
 * \brief The AVX512 depth multiplier for cache operations.
 *
 * \details
 * Specifies the number of simultaneous operations when using the (x8) SIMD API.
 */
#define HKDS_CACHX8_DEPTH 8U

/*!
 * \def HKDS_CACHX64_SIZE
 * \brief The total number of tokens when using the multi-threaded/SIMD 3-d array (x64) API.
 */
#define HKDS_CACHX64_SIZE 64U

/*!
 * \def HKDS_CTOK_SIZE
 * \brief Internal size of the token customization string.
 */
#define HKDS_CTOK_SIZE 23U

/*!
 * \def HKDS_DID_SIZE
 * \brief The device identity size in bytes.
 */
#define HKDS_DID_SIZE 12U

/*!
 * \def HKDS_ERROR_SIZE
 * \brief The error message size in bytes.
 */
#define HKDS_ERROR_SIZE 16U

/*!
 * \def HKDS_HEADER_SIZE
 * \brief The size of the HKDS packet header in bytes.
 */
#define HKDS_HEADER_SIZE 4U

/*!
 * \def HKDS_KID_SIZE
 * \brief The master key identity string size in bytes.
 */
#define HKDS_KID_SIZE 4U

/*!
 * \def HKDS_KSN_SIZE
 * \brief The Key Serial Number (KSN) size in bytes.
 */
#define HKDS_KSN_SIZE 16U

/*!
 * \def HKDS_MESSAGE_SIZE
 * \brief The encrypted message size in bytes.
 */
#define HKDS_MESSAGE_SIZE 16U

/*!
 * \def HKDS_NAME_SIZE
 * \brief Internal: The formal algorithm name size in bytes.
 */
#define HKDS_NAME_SIZE 7U

/*!
 * \def HKDS_TAG_SIZE
 * \brief The size of the authentication tag (MAC) in bytes.
 */
#define HKDS_TAG_SIZE 16U

/*!
 * \def HKDS_TKC_SIZE
 * \brief The transaction key counter size (big endian) in bytes.
 */
#define HKDS_TKC_SIZE 4U

/*!
 * \def HKDS_TMS_SIZE
 * \brief The size of the token MAC string.
 *
 * \details
 * This value is computed as the sum of the KSN size and the formal name size.
 */
#define HKDS_TMS_SIZE (HKDS_KSN_SIZE + HKDS_NAME_SIZE)

#if defined(HKDS_SHAKE_128)

/*!
 * \def HKDS_BDK_SIZE
 * \brief The Base Derivation Key size for SHAKE-128 in bytes.
 */
#	define HKDS_BDK_SIZE 16U

/*!
 * \def HKDS_EDK_SIZE
 * \brief The Embedded Device Key size for SHAKE-128 in bytes.
 */
#	define HKDS_EDK_SIZE 16U

/*!
 * \def HKDS_ETOK_SIZE
 * \brief The encrypted token (server response) size for SHAKE-128 in bytes.
 */
#	define HKDS_ETOK_SIZE 32U

/*!
 * \def HKDS_PRF_RATE
 * \brief The output length of the underlying PRF (SHAKE-128) in bytes.
 */
#	define HKDS_PRF_RATE 168U

/*!
 * \def HKDS_PROTOCOL_TYPE
 * \brief The protocol type supported by this implementation (SHAKE-128).
 */
#	define HKDS_PROTOCOL_TYPE protocol_shake_128

/*!
 * \def HKDS_STK_SIZE
 * \brief The Secret Token Key size for SHAKE-128 in bytes.
 */
#	define HKDS_STK_SIZE 16U

/*!
 * \brief The formal algorithm name for HKDS SHAKE-128.
 */
static const uint8_t hkds_formal_name[HKDS_NAME_SIZE] = { 0x48U, 0x4BU, 0x44U, 0x53U, 0x31U, 0x32U, 0x38U };

/*!
 * \brief The KMAC name for HKDS SHAKE-128.
 */
static const uint8_t hkds_mac_name[HKDS_NAME_SIZE] = { 0x75U, 0x4BU, 0x77U, 0x65U, 0x31U, 0x32U, 0x38U };

#elif defined(HKDS_SHAKE_256)

/*!
 * \def HKDS_BDK_SIZE
 * \brief The Base Derivation Key size for SHAKE-256 in bytes.
 */
#	define HKDS_BDK_SIZE 32U

/*!
 * \def HKDS_EDK_SIZE
 * \brief The Embedded Device Key size for SHAKE-256 in bytes.
 */
#	define HKDS_EDK_SIZE 32U

/*!
 * \def HKDS_ETOK_SIZE
 * \brief The encrypted token (server response) size for SHAKE-256 in bytes.
 */
#	define HKDS_ETOK_SIZE 48U

/*!
 * \def HKDS_PRF_RATE
 * \brief The output length of the underlying PRF (SHAKE-256) in bytes.
 */
#	define HKDS_PRF_RATE 136U

/*!
 * \def HKDS_PROTOCOL_TYPE
 * \brief The protocol type supported by this implementation (SHAKE-256).
 */
#	define HKDS_PROTOCOL_TYPE protocol_shake_256

/*!
 * \def HKDS_STK_SIZE
 * \brief The Secret Token Key size for SHAKE-256 in bytes.
 */
#	define HKDS_STK_SIZE 32U

/*!
 * \brief The formal algorithm name for HKDS SHAKE-256.
 */
static const uint8_t hkds_formal_name[HKDS_NAME_SIZE] = { 0x48, 0x4B, 0x44, 0x53, 0x32, 0x35, 0x36 };

/*!
 * \brief The KMAC name for HKDS SHAKE-256.
 */
static const uint8_t hkds_mac_name[HKDS_NAME_SIZE] = { 0x75, 0x4B, 0x77, 0x65, 0x32, 0x35, 0x36 };

#elif defined(HKDS_SHAKE_512)

/*!
 * \def HKDS_BDK_SIZE
 * \brief The Base Derivation Key size for SHAKE-512 in bytes.
 */
#	define HKDS_BDK_SIZE 64U

/*!
 * \def HKDS_EDK_SIZE
 * \brief The Embedded Device Key size for SHAKE-512 in bytes.
 */
#	define HKDS_EDK_SIZE 64U

/*!
 * \def HKDS_ETOK_SIZE
 * \brief The encrypted token (server response) size for SHAKE-512 in bytes.
 */
#	define HKDS_ETOK_SIZE 80U

/*!
 * \def HKDS_PRF_RATE
 * \brief The output length of the underlying PRF (SHAKE-512) in bytes.
 */
#	define HKDS_PRF_RATE 72U

/*!
 * \def HKDS_PROTOCOL_TYPE
 * \brief The protocol type supported by this implementation (SHAKE-512).
 */
#	define HKDS_PROTOCOL_TYPE protocol_shake_512

/*!
 * \def HKDS_STK_SIZE
 * \brief The Secret Token Key size for SHAKE-512 in bytes.
 */
#	define HKDS_STK_SIZE 64U

/*!
 * \brief The formal algorithm name for HKDS SHAKE-512.
 */
static const uint8_t hkds_formal_name[HKDS_NAME_SIZE] = { 0x48, 0x4B, 0x44, 0x53, 0x35, 0x31, 0x32 };

/*!
 * \brief The KMAC name for HKDS SHAKE-512.
 */
static const uint8_t hkds_mac_name[HKDS_NAME_SIZE] = { 0x75, 0x4B, 0x77, 0x65, 0x35, 0x31, 0x32 };

#endif

/*!
 * \def HKDS_CACHE_SIZE
 * \brief The size of the transaction key cache.
 *
 * \details
 * Calculated as ((HKDS_CACHE_MULTIPLIER * HKDS_PRF_RATE) / HKDS_MESSAGE_SIZE).
 */
#define HKDS_CACHE_SIZE ((HKDS_CACHE_MULTIPLIER * HKDS_PRF_RATE) / HKDS_MESSAGE_SIZE)

/*!
 * \def HKDS_CLIENT_MESSAGE_REQUEST_SIZE
 * \brief The size of the client message request packet.
 *
 * \details
 * This size is computed as the sum of the header size, KSN size, message size, and tag size.
 */
#define HKDS_CLIENT_MESSAGE_REQUEST_SIZE (HKDS_HEADER_SIZE + HKDS_KSN_SIZE + HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE)

/*!
 * \def HKDS_CLIENT_TOKEN_REQUEST_SIZE
 * \brief The size of the client token request packet.
 *
 * \details
 * This size is computed as the sum of the header size and the KSN size.
 */
#define HKDS_CLIENT_TOKEN_REQUEST_SIZE (HKDS_HEADER_SIZE + HKDS_KSN_SIZE)

/*!
 * \def HKDS_SERVER_MESSAGE_RESPONSE_SIZE
 * \brief The size of the server message response packet.
 *
 * \details
 * This size is computed as the sum of the header size and the message size.
 */
#define HKDS_SERVER_MESSAGE_RESPONSE_SIZE (HKDS_HEADER_SIZE + HKDS_MESSAGE_SIZE)

/*!
 * \def HKDS_SERVER_TOKEN_RESPONSE_SIZE
 * \brief The size of the server token response packet.
 *
 * \details
 * This size is computed as the sum of the header size and the encrypted token size.
 */
#define HKDS_SERVER_TOKEN_RESPONSE_SIZE (HKDS_HEADER_SIZE + HKDS_ETOK_SIZE)

/*!
 * \def HKDS_ADMIN_MESSAGE_SIZE
 * \brief The size of the administrative message packet.
 *
 * \details
 * This size is computed as the sum of the header size and the administrative message size.
 */
#define HKDS_ADMIN_MESSAGE_SIZE (HKDS_HEADER_SIZE + HKDS_ADMIN_SIZE)

/*!
 * \def HKDS_ERROR_MESSAGE_SIZE
 * \brief The size of the error message packet.
 *
 * \details
 * This size is computed as the sum of the header size and the error message size.
 */
#define HKDS_ERROR_MESSAGE_SIZE (HKDS_HEADER_SIZE + HKDS_ERROR_SIZE)

/*** Packet Headers ***/

/*!
 * \struct hkds_packet_header
 * \brief The primary header for all HKDS messages.
 *
 * \details
 * This structure represents the common header present at the beginning of every HKDS packet. It contains:
 * - \c flag: The packet type.
 * - \c protocol: The protocol identifier (indicating the SHAKE variant).
 * - \c sequence: The packet sequence number.
 * - \c length: The total length of the packet (including the header).
 */
typedef struct
{
    hkds_packet_type flag;      /*!< The type of packet */
    hkds_protocol_id protocol;  /*!< The protocol identifier */
    uint8_t sequence;           /*!< The packet sequence number */
    uint8_t length;             /*!< The packet size including header */
} hkds_packet_header;

/*!
 * \struct hkds_client_message_request
 * \brief Represents the client's encrypted message request packet.
 *
 * \details
 * This structure defines the layout of the client message request packet. It contains:
 * - A common HKDS packet header.
 * - The client's Key Serial Number (KSN).
 * - The encrypted message.
 * - An optional authentication tag (MAC) appended to the message.
 */
typedef struct
{
    hkds_packet_header header;         /*!< The HKDS packet header */
    uint8_t ksn[HKDS_KSN_SIZE];         /*!< The client's Key Serial Number (KSN) */
    uint8_t message[HKDS_MESSAGE_SIZE];  /*!< The client's encrypted message */
    uint8_t tag[HKDS_TAG_SIZE];          /*!< The optional authentication tag */
} hkds_client_message_request;

/*!
 * \struct hkds_client_token_request
 * \brief Represents the client token request packet.
 *
 * \details
 * The client token request packet is sent to the server during initialization and each time the transaction key cache
 * is exhausted. It includes:
 * - A common HKDS packet header.
 * - The client's Key Serial Number (KSN).
 */
typedef struct
{
    hkds_packet_header header;         /*!< The HKDS packet header */
    uint8_t ksn[HKDS_KSN_SIZE];         /*!< The client's Key Serial Number (KSN) */
} hkds_client_token_request;

/*!
 * \struct hkds_server_message_response
 * \brief Represents the server's plaintext message response packet.
 *
 * \details
 * This structure defines the layout of the server message response packet, which typically contains a verification response
 * indicating the outcome of a transaction request. It includes:
 * - A common HKDS packet header.
 * - The server's plaintext message response.
 */
typedef struct
{
    hkds_packet_header header;         /*!< The HKDS packet header */
    uint8_t message[HKDS_MESSAGE_SIZE];  /*!< The server's message response */
} hkds_server_message_response;

/*!
 * \struct hkds_server_token_response
 * \brief Represents the server's token response packet.
 *
 * \details
 * The server token response packet contains the encrypted token (ETOK) generated by the server in response to a client token
 * request. It includes:
 * - A common HKDS packet header.
 * - The server's encrypted token.
 */
typedef struct
{
    hkds_packet_header header;         /*!< The HKDS packet header */
    uint8_t etok[HKDS_ETOK_SIZE];        /*!< The server's encrypted token */
} hkds_server_token_response;

/*!
 * \struct hkds_administrative_message
 * \brief Represents an administrative message packet.
 *
 * \details
 * Administrative messages are used to signal requests, status updates, or to reset a communications session following an error.
 * This structure contains:
 * - A common HKDS packet header.
 * - The administrative message payload.
 */
typedef struct
{
    hkds_packet_header header;         /*!< The HKDS packet header */
    uint8_t message[HKDS_ADMIN_SIZE];    /*!< The administrative message payload */
} hkds_administrative_message;

/*!
 * \struct hkds_error_message
 * \brief Represents an error message packet.
 *
 * \details
 * An error message indicates a serious failure between the client and server. This bidirectional message contains:
 * - A common HKDS packet header.
 * - The error message payload.
 */
typedef struct
{
    hkds_packet_header header;         /*!< The HKDS packet header */
    uint8_t message[HKDS_ERROR_SIZE];    /*!< The error message payload */
} hkds_error_message;

#endif
