
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

#ifndef HKDS_CONFIG_H
#define HKDS_CONFIG_H

#include "common.h"

 /* Enumerations */

/*! \enum hkds_packet_type
* The packet type enumeration, the type of message contained in the packet.
*/
typedef enum hkds_packet_type
{
	packet_token_request = 0x01,				/*!< A client token request */
	packet_token_response = 0x02,				/*!< A server token response */
	packet_message_request = 0x03,				/*!< A client message request */
	packet_message_response = 0x04,				/*!< A server message response */
	packet_administrative_message = 0x05,		/*!< An administrative message */
	packet_error_message = 0x06,				/*!< An error message */
} 
hkds_packet_type;

/*! \enum hkds_protocol_id
* The base cryptographic protocol type enumeration, defines the security of the implementation.
*/
typedef enum hkds_protocol_id
{
	protocol_shake_128 = 0x09,					/*!< Protocol is SHAKE-128 */
	protocol_shake_256 = 0x0A,					/*!< Protocol is SHAKE-256 */
	protocol_shake_512 = 0x0B,					/*!< Protocol is SHAKE-512 */
} 
hkds_protocol_id;

/*! \enum hkds_message_types
* The HKDS packet error type enumeration.
*/
typedef enum hkds_error_type
{
	error_general_failure = 0x1F,				/*!< General failure */
	error_connection_aborted = 0x21,			/*!< The connection was aborted by the remote host */
	error_disconnected = 0x22,					/*!< The network link was lost */
	error_connection_refused = 0x23,			/*!< The connection was refused by the remote host */
	error_invalid_format = 0x24,				/*!< The request format was invalid */
	error_retries_exceeded = 0x25,				/*!< The allowed number of retries was exceeded */
	error_connection_failure = 0x26,			/*!< The connection had a general failure */
	error_unkown_failure = 0xFF,				/*!< The cause of failure is unknown */
}
hkds_error_type;

/*! \enum hkds_message_types
* The HKDS packet message type enumeration
*/
typedef enum hkds_message_type
{
	message_synchronize_token = 0x01,			/*!< Sent by the client INDICATING A token key received from the server failed an authentication check */
	message_reinitialized_token	= 0x02,			/*!< The server�s [optional] response to the client token key rejection  */
	message_token_requests_exceeded = 0x03,		/*!< The server indicates the maximum number of token failures have occurred  */
	message_remote_reset = 0x04,				/*!< The server sends a remote reset to the client terminal */
	message_diagnostic = 0x05,					/*!< The server requests a diagnostic output from the terminal�s hardware components */
	message_reserved1 = 0x06,					/*!< Reseved message 1 */
	message_reserved2 = 0x07,					/*!< Reseved message 2 */
	message_reserved3 = 0x08,					/*!< Reseved message 3 */
} 
hkds_message_type;

/*** Modifiable values: ***/

/*!
\def HKDS_KECCAK_DOUBLE_ROUNDS
* HKDS runs using Keccak with 48 rounds instead of the standard 24
*/
//#define HKDS_KECCAK_DOUBLE_ROUNDS

/*!
\def HKDS_KECCAK_HALF_ROUNDS
* HKDS runs using Keccak with 12 rounds instead of the standard 24
*/
//#define HKDS_KECCAK_HALF_ROUNDS

/*!
\def HKDS_SHAKE_128
* Implement the SHAKE-128 version of HKDS
*/
//#define HKDS_SHAKE_128

/*!
\def HKDS_SHAKE_256
* Implement the SHAKE-256 version of HKDS
*/
#define HKDS_SHAKE_256

/*!
\def HKDS_SHAKE_512
* Implement the SHAKE-512 version of HKDS
*/
//#define HKDS_SHAKE_512

/*!
\def HKDS_CACHE_MULTIPLIER
* The transaction key cache multiplier.
* Changes the size of the transaction key cache. 
* Must be a multiple of 2; allowed size are 2, 4, 6, 8, 10, and 12.
* A larger cache means fewer token exchanges, but a slower decryption,
* and a larger client cache size.
* The recommended value is 4, and not exceeding 8.
*/
#define HKDS_CACHE_MULTIPLIER 4

/*** Static values (do not change) ***/

/*!
\def HKDS_ADMIN_SIZE
* The administrative message size
*/
#define HKDS_ADMIN_SIZE 2

/*!
\def HKDS_AUTHENTICATION_MODE
* The KMAC authentication mode designator contained in a clients DID
*/
#define HKDS_AUTHENTICATION_KMAC 0x11

/*!
\def HKDS_AUTHENTICATION_NONE
* The authentication mode set to none
*/
#define HKDS_AUTHENTICATION_NONE 0x10

/*!
\def HKDS_AUTHENTICATION_MODE
* The SHA3 authentication mode designator contained in a clients DID
*/
#define HKDS_AUTHENTICATION_SHA3 0x12

/*!
\def HKDS_PARALLEL_DEPTH
* The AVX512 depth multiplier.
* The number of simultaneous server decryption and token generations when using the (x8) SIMD api.
*/
#define HKDS_PARALLEL_DEPTH 8

/*!
\def HKDS_CACHX8_DEPTH
* The AVX512 depth multiplier.
* The number of simultaneous server decryption and token generations when using the (x8) SIMD api.
*/
#define HKDS_CACHX8_DEPTH 8

/*!
\def HKDS_CACHX64_SIZE
* The parallel/SIMD items count.
* The total number of tokens when using the multi-threaded/SIMD 3-d array (x64) api.
*/
#define HKDS_CACHX64_SIZE 64

/*!
\def HKDS_CTOK_SIZE
* Internal: the token keys cutstom string size
*/
#define HKDS_CTOK_SIZE 23

/*!
\def HKDS_DID_SIZE
* Internal: The device identity size
*/
#define HKDS_DID_SIZE 12

/*!
\def HKDS_ERROR_SIZE
* The error message size
*/
#define HKDS_ERROR_SIZE 16

/*!
\def HKDS_HEADER_SIZE
* The HKDS packet header byte size
*/
#define HKDS_HEADER_SIZE 4

/*!
\def HKDS_KID_SIZE
* The master key identity string size
*/
#define HKDS_KID_SIZE 4

/*!
\def HKDS_KSN_SIZE
* The key serial number size
*/
#define HKDS_KSN_SIZE 16

/*!
\def HKDS_MESSAGE_SIZE
* The encrypted message size
*/
#define HKDS_MESSAGE_SIZE 16

/*!
\def HKDS_NAME_SIZE
* Internal: the formal name size
*/
#define HKDS_NAME_SIZE 7

/*!
\def HKDS_TAG_SIZE
* The size of the authentication code tag used with authenticated encryption
*/
#define HKDS_TAG_SIZE 16

/*!
\def HKDS_TKC_SIZE
* The transaction key counter (big endian)
*/
#define HKDS_TKC_SIZE 4

/*!
\def HKDS_TMS_SIZE
* The token MAC string size
*/
#define HKDS_TMS_SIZE (HKDS_KSN_SIZE + HKDS_NAME_SIZE)

#if defined(HKDS_SHAKE_128)

/*!
\def HKDS_BDK_SIZE
* The base derivation key size
*/
#	define HKDS_BDK_SIZE 16

/*!
\def HKDS_EDK_SIZE
* The embedded device key size
*/
#	define HKDS_EDK_SIZE 16

/*!
\def HKDS_ETOK_SIZE
* The encrypted token server response size
*/
#	define HKDS_ETOK_SIZE 32

/*!
\def HKDS_PRF_RATE
* The output length of the underlying prf
*/
#	define HKDS_PRF_RATE 168

/*!
\def HKDS_PROTOCOL_TYPE
* The protocol supported by this implementation
*/
#	define HKDS_PROTOCOL_TYPE protocol_shake_128

/*!
\def HKDS_STK_SIZE
* The secret token key size
*/
#	define HKDS_STK_SIZE 16

	static const uint8_t hkds_mac_name[HKDS_NAME_SIZE] = { 0x75, 0x4B, 0x77, 0x65, 0x31, 0x32, 0x38 };

	static const uint8_t hkds_formal_name[HKDS_NAME_SIZE] = { 0x48, 0x4B, 0x44, 0x53, 0x31, 0x32, 0x38 };

#elif defined(HKDS_SHAKE_256)

/*!
\def HKDS_BDK_SIZE
* The base derivation key size
*/
#	define HKDS_BDK_SIZE 32

/*!
\def HKDS_EDK_SIZE
* The embedded device key size
*/
#	define HKDS_EDK_SIZE 32

/*!
\def HKDS_ETOK_SIZE
* The encrypted token server response size
*/
#	define HKDS_ETOK_SIZE 48

/*!
\def HKDS_PRF_RATE
* The output length of the underlying prf
*/
#	define HKDS_PRF_RATE 136

/*!
\def HKDS_PROTOCOL_TYPE
* The protocol supported by this implementation
*/
#	define HKDS_PROTOCOL_TYPE protocol_shake_256

/*!
\def HKDS_STK_SIZE
* The secret token key size
*/
#	define HKDS_STK_SIZE 32

	static const uint8_t hkds_formal_name[HKDS_NAME_SIZE] = { 0x48, 0x4B, 0x44, 0x53, 0x32, 0x35, 0x36 };

	static const uint8_t hkds_mac_name[HKDS_NAME_SIZE] = { 0x75, 0x4B, 0x77, 0x65, 0x32, 0x35, 0x36 };

#elif defined(HKDS_SHAKE_512)

/*!
\def HKDS_BDK_SIZE
* The base derivation key size
*/
#	define HKDS_BDK_SIZE 64

/*!
\def HKDS_EDK_SIZE
* The embedded device key size
*/
#	define HKDS_EDK_SIZE 64

/*!
\def HKDS_ETOK_SIZE
* The encrypted token server response size
*/
#	define HKDS_ETOK_SIZE 80

/*!
\def HKDS_PRF_RATE
* The output length of the underlying prf
*/
#	define HKDS_PRF_RATE 72

/*!
\def HKDS_PROTOCOL_TYPE
* The protocol supported by this implementation
*/
#	define HKDS_PROTOCOL_TYPE protocol_shake_512

/*!
\def HKDS_STK_SIZE
* The secret token key size
*/
#	define HKDS_STK_SIZE 64

	static const uint8_t hkds_formal_name[HKDS_NAME_SIZE] = { 0x48, 0x4B, 0x44, 0x53, 0x35, 0x31, 0x32 };

	static const uint8_t hkds_mac_name[HKDS_NAME_SIZE] = { 0x75, 0x4B, 0x77, 0x65, 0x35, 0x31, 0x32 };

#endif

/*!
\def HKDS_CACHE_SIZE
* The size of the transaction key cache
*/
#define HKDS_CACHE_SIZE ((HKDS_CACHE_MULTIPLIER * HKDS_PRF_RATE) / HKDS_MESSAGE_SIZE)

/*!
\def HKDS_CLIENT_MESSAGE_REQUEST_SIZE
* The client message request packet size
*/
#define HKDS_CLIENT_MESSAGE_REQUEST_SIZE (HKDS_HEADER_SIZE + HKDS_KSN_SIZE + HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE)

/*!
\def HKDS_CLIENT_TOKEN_REQUEST_SIZE
* The client token request packet size
*/
#define HKDS_CLIENT_TOKEN_REQUEST_SIZE (HKDS_HEADER_SIZE + HKDS_KSN_SIZE)

/*!
\def HKDS_SERVER_MESSAGE_RESPONSE_SIZE
* The server message response packet size
*/
#define HKDS_SERVER_MESSAGE_RESPONSE_SIZE (HKDS_HEADER_SIZE + HKDS_MESSAGE_SIZE)

/*!
\def HKDS_SERVER_TOKEN_RESPONSE_SIZE
* The server token response packet size
*/
#define HKDS_SERVER_TOKEN_RESPONSE_SIZE (HKDS_HEADER_SIZE + HKDS_ETOK_SIZE)

/*!
\def HKDS_ADMIN_MESSAGE_SIZE
* The administrative message packet size
*/
#define HKDS_ADMIN_MESSAGE_SIZE (HKDS_HEADER_SIZE + HKDS_ADMIN_SIZE)

/*!
\def HKDS_ADMIN_MESSAGE_SIZE
* The error message packet size
*/
#define HKDS_ERROR_MESSAGE_SIZE (HKDS_HEADER_SIZE + HKDS_ERROR_SIZE)

/*** Packet Headers ***/

/*! \struct hkds_packet_header
* The primary header for all HKDS messages.
*/
typedef struct
{
	hkds_packet_type flag;					/*!< The type of packet */
	hkds_protocol_id protocol;				/*!< The protocol id */
	uint8_t sequence;						/*!< The packet sequence */
	uint8_t length;							/*!< The packet size including header */
}
hkds_packet_header;

/*! \struct hkds_client_message_request
* The client�s encrypted request message packet. 
* This packet includes 16 bytes of encrypted message and the client�s key serial number, 
* and may include the authentication tag as indicated by the Protocol ID flag.
*/
typedef struct
{
	hkds_packet_header header;				/*!< The HKDS packet header */
	uint8_t ksn[HKDS_KSN_SIZE];				/*!< The client's KSN */
	uint8_t message[HKDS_MESSAGE_SIZE];		/*!< The clients encrypted message */
	uint8_t tag[HKDS_TAG_SIZE];				/*!< The optional authentication tag */
}
hkds_client_message_request;

/*! \struct hkds_client_token_request
* The client token request is sent to the server on initialization and subsequently each time 
* the transaction key cache has been exhausted.
*/
typedef struct
{
	hkds_packet_header header;				/*!< The HKDS packet header */
	uint8_t ksn[HKDS_KSN_SIZE];				/*!< The client's KSN */
}
hkds_client_token_request;

/*! \struct hkds_server_message_response
* The server�s plaintext message response, typically a verification response sent to the client terminal 
* that indicates the success or failure of a transaction request.
*/
typedef struct
{
	hkds_packet_header header;				/*!< The HKDS packet header */
	uint8_t message[HKDS_MESSAGE_SIZE];		/*!< The servers message response */
}
hkds_server_message_response;

/*! \struct hkds_server_token_response
* The server�s response to a token request. 
* This packet contains an encrypted token (ETOK) sent from the server to the client device. 
*/
typedef struct
{
	hkds_packet_header header;				/*!< The HKDS packet header */
	uint8_t etok[HKDS_ETOK_SIZE];			/*!< The severs encrypted token */
}
hkds_server_token_response;

/*! \struct hkds_administrative_message
* An administrative message is used to signal requests, status updates, 
* or as a post-error condition reset of a communications session. 
*/
typedef struct
{
	hkds_packet_header header;				/*!< The HKDS packet header */
	uint8_t message[HKDS_ADMIN_SIZE];		/*!< The administrative message */
}
hkds_administrative_message;

/*! \struct hkds_error_message
* An error message indicates a serious failure between the client or server. 
* This message is bi-directional and can be sent by either the client or server. 
*/
typedef struct
{
	hkds_packet_header header;				/*!< The HKDS packet header */
	uint8_t message[HKDS_ERROR_SIZE];		/*!< The error message */
}
hkds_error_message;

#endif
