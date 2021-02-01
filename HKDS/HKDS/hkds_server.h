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
 * Written on March 29, 2020
 * Updated on November 24, 2020
 * Contact: develop@dfdef.com
 */

#ifndef HKDS_SERVER_H
#define HKDS_SERVER_H

#include "hkds_config.h"

 /*! \struct hkds_master_key
 * Contains the HKDS master key set
 */
HKDS_EXPORT_API typedef struct
{
	uint8_t bdk[HKDS_BDK_SIZE];	/*!< The base derivation key */
	uint8_t stk[HKDS_STK_SIZE];	/*!< The secret token key */
	uint8_t kid[HKDS_KID_SIZE];	/*!< The key identity */
} hkds_master_key;

/*! \struct hkds_server_state
* Contains the HKDS server state
*/
HKDS_EXPORT_API typedef struct
{
	uint8_t ksn[HKDS_KSN_SIZE];	/*!< The key serial number array */
	hkds_master_key* mdk;		/*!< A pointer to the master derivation key */
	size_t count;				/*!< The token count */
	size_t rate;				/*!< The derivation functions rate */
} hkds_server_state;

/**
* \brief Decrypt a message sent by the client.
*
* \param state [struct] The function state
* \param ciphertext [array][const] The encrypted message
* \param plaintext [array][output] The decrypted message output
*/
HKDS_EXPORT_API void hkds_server_decrypt_message(hkds_server_state* state, const uint8_t* ciphertext, uint8_t* plaintext);

/**
* \brief Verify a ciphertext's integrity with a keyed MAC, if verified return the decrypted PIN message.
* This function uses KMAC to verify the cipher-text integrity before decrypting the message.
* An optional data can be added to the MAC update, such as the originating clients IP address.
* If the MAC verifies the cipher-text, the message is decrypted and returned by this function.
* If the MAC authentication check fails, the function returns false and the plaintext is zeroed.
*
* \param state [struct] The function state
* \param ciphertext [array][const] The encrypted message
* \param data [array][const] The additional data array
* \param datalen [size] The length of the additional data array
* \param plaintext [array][output] The decrypted message output
* \return [bool] Returns true if the message was authenticated, false with zeroed plaintext on failure
*/
HKDS_EXPORT_API bool hkds_server_decrypt_verify_message(hkds_server_state* state, const uint8_t* ciphertext, const uint8_t* data,
	size_t datalen, uint8_t* plaintext);

/**
* \brief Encrypt a secret token key to send to the client.
*
* \param state [struct] The function state
* \param etok [array][output] The encrypted token output key array
*/
HKDS_EXPORT_API void hkds_server_encrypt_token(hkds_server_state* state, uint8_t* etok);

/**
* \brief Generate the embedded device key of a client.
*
* \param bdk [array][const] The base derivation key
* \param did [array][const] The devices unique identity string
* \param edk [array][output] The embedded device key output array
*/
HKDS_EXPORT_API void hkds_server_generate_edk(const uint8_t* bdk, const uint8_t* did, uint8_t* edk);

/**
* \brief Generate a master key set.
*
* \param rng_generate [pointer] A pointer to the random generator function
* \param mdk [struct] The output master key set
* \param kid [array][const] The master key identity string
*/
HKDS_EXPORT_API void hkds_server_generate_mdk(void (*rng_generate)(uint8_t*, size_t), hkds_master_key* mdk, const uint8_t* kid);

/**
* \brief Initialize the state with the embedded device key and device identity.
*
* \param state [struct] The function state
* \param mdk [struct] The master key set
* \param ksn [array][const] The clients key serial number
*/
HKDS_EXPORT_API void hkds_server_initialize_state(hkds_server_state* state, hkds_master_key* mdk, const uint8_t* ksn);

/* SIMD vectorized x8 api */

/*! \struct hkds_server_state
* Contains the HKDS server state
*/
HKDS_EXPORT_API typedef struct
{
	uint8_t ksn[HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE];	/*!< The clients key serial number 2d array */
	hkds_master_key* mdk;							/*!< A pointer to the master derivation key struct */
} 
hkds_server_x8_state;

/**
* \brief Decrypt a 2-dimensional x8 set of client messages.
*
* \param state [array][struct] A set of function states
* \param ciphertext [array2d][const] A set of encrypted messages
* \param plaintext [array2d][output] A set of decrypted message outputs
*/
HKDS_EXPORT_API void hkds_server_decrypt_message_x8(hkds_server_x8_state* state, 
	const uint8_t ciphertext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE],
	uint8_t plaintext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
* \brief Verify a 2-dimensional x8 set of ciphertext's integrity with a keyed MAC, if verified return the decrypted PIN message.
* This function uses KMAC to verify the cipher-text integrity before decrypting the message.
* An optional data can be added to the MAC update, such as the originating clients IP address.
* If the MAC verifies the cipher-text, the message is decrypted and returned by this function.
* If the MAC authentication check fails, the function returns false and the plaintext is zeroed.
*
* \param state [array][struct] A set of function states
* \param ciphertext [array2d][const] A set of encrypted messages
* \param data [array2d][const] A set of additional data arrays
* \param datalen [size] The length of the additional data arrays
* \param plaintext [array2d][output] A set of decrypted message outputs
* \param valid [array][output] A set of booleans, indicating the verification of each messsage
*/
HKDS_EXPORT_API void hkds_server_decrypt_verify_message_x8(hkds_server_x8_state* state, 
	const uint8_t ciphertext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE],
	const uint8_t data[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], size_t datalen, 
	uint8_t plaintext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], 
	bool valid[HKDS_CACHX8_DEPTH]);

/**
* \brief Encrypt a 2-dimensional x8 set of secret token keys.
*
* \param state [array][struct] A set of function states
* \param etok [array2d][output] A set of encrypted token output key arrays
*/
HKDS_EXPORT_API void hkds_server_encrypt_token_x8(hkds_server_x8_state* state, uint8_t etok[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE]);

/**
* \brief Generate a 2-dimensional x8 set of client embedded device keys.
*
* \param state [array][struct] A set of function states
* \param did [array2d][const] A set of device unique identity strings
* \param edk [array2d][output] A set of embedded device key output array
*/
HKDS_EXPORT_API void hkds_server_generate_edk_x8(hkds_server_x8_state* state, 
	const uint8_t did[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE],
	uint8_t edk[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE]);

/**
* \brief Initialize a 2-dimensional x8 set of server states with the embedded device keys and device identities.
*
* \param state [array][struct] A set of function states
* \param mdk [struct] A set of master key sets
* \param ksn [array2d][const] A set of clients key serial numbers
*/
HKDS_EXPORT_API void hkds_server_initialize_state_x8(hkds_server_x8_state* state, 
	hkds_master_key* mdk, 
	const uint8_t ksn[HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE]);

/* Parallel and SIMD vectorized x64 api */

/**
* \brief Decrypt a 3-dimensional 8x8 set of client messages.
*
* \param state [array][struct] A set of function states
* \param ciphertext [array3d][const] A set of encrypted messages
* \param plaintext [array3d][output] A set of decrypted messages
*/
HKDS_EXPORT_API void hkds_server_decrypt_message_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
	const uint8_t ciphertext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE],
	uint8_t plaintext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
* \brief Verify a 3-dimensional 8x8 set of ciphertext's integrity with a keyed MAC, if verified return the decrypted PIN message.
* This function uses KMAC to verify the cipher-text integrity before decrypting the message.
* An optional data can be added to the MAC update, such as the originating clients IP address.
* If the MAC verifies the cipher-text, the message is decrypted and returned by this function.
* If the MAC authentication check fails, the function returns false and the plaintext is zeroed.
*
* \param state [array][struct] A set of function states
* \param ciphertext [array3d][const] A set of encrypted messages
* \param data [array3d][const] A set of additional data arrays
* \param datalen [size] The length of the additional data arrays
* \param plaintext [array3d][output] A set of decrypted messages
* \param valid [array2d][output] A set of booleans, indicating the verification of each messsage
*/
HKDS_EXPORT_API void hkds_server_decrypt_verify_message_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
	const uint8_t ciphertext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE],
	const uint8_t data[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], size_t datalen,
	uint8_t plaintext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE],
	bool valid[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH]);


/**
* \brief Encrypt a 3-dimensional 8x8 set of secret token keys.
*
* \param state [array][struct] A set of function states
* \param etok [array3d][output] A set of encrypted token output key arrays
*/
HKDS_EXPORT_API void hkds_server_encrypt_token_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH], uint8_t etok[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE]);

/**
* \brief Generate a 3-dimensional 8x8 set of client embedded device keys.
*
* \param state [array][struct] A set of function states
* \param did [array3d][const] A set of device unique identity strings
* \param edk [array3d][output] A set of embedded device key output array
*/
HKDS_EXPORT_API void hkds_server_generate_edk_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
	const uint8_t did[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_DID_SIZE],
	uint8_t edk[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE]);

/**
* \brief Initialize a 3-dimensional 8x8 set of server states with the embedded device keys and device identities.
*
* \param state [array][struct] A set of function states
* \param mdk [array3d][struct] A set of master key sets*
* \param ksn [array3d][const] A set of clients key serial numbers
*/
HKDS_EXPORT_API void hkds_server_initialize_state_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
	hkds_master_key mdk[HKDS_PARALLEL_DEPTH],
	const uint8_t ksn[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE]);

#endif
