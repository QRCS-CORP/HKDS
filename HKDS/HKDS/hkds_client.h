
/* 2021 Digital Freedom Defense Incorporated
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
 * Updated on December 9, 2021
 * Contact: develop@dfdef.com
 */

#ifndef HKDS_CLIENT_H
#define HKDS_CLIENT_H

#include "hkds_config.h"

/*! \struct hkds_client_state
* Contains the HKDS client state
*/
HKDS_EXPORT_API typedef struct
{
	uint8_t edk[HKDS_EDK_SIZE];
	uint8_t ksn[HKDS_KSN_SIZE];
	uint8_t tkc[HKDS_CACHE_SIZE][HKDS_MESSAGE_SIZE];
	bool cache_empty;
} hkds_client_state;

/**
* \brief Decrypt an encrypted token key sent by the server
*
* \param state [struct] The function state
* \param etok [const][array] The encrypted token key
* \param token [output][array] The output decrypted token key
*/
HKDS_EXPORT_API bool hkds_client_decrypt_token(hkds_client_state* state, const uint8_t* etok, uint8_t* token);

/**
* \brief Encrypt a message to be sent to the server
*
* \param state [struct] The function state
* \param plaintext [const][array] The plaintext message
* \param ciphertext [output][array] The encrypted message to send
* \return [bool] Returns true if the message was encrypted, false if key-cache is empty
*/
HKDS_EXPORT_API bool hkds_client_encrypt_message(hkds_client_state* state, const uint8_t* plaintext, uint8_t* ciphertext);

/**
* \brief Encrypt a message and add an authentication tag.
* The PIN is first encrypted, then the cipher-text is used to update a keyed KMAC function.
* An optional data can be added to the MAC update, such as the IP address of the client.
* The authentication tag is appended to the encrypted PIN and returned by the function.
*
* \param state [struct] The function state
* \param plaintext [const][array] The plaintext message
* \param data [const][array] The additional data array
* \param datalen [size] The length of the additional data array
* \param ciphertext [output][array] The encrypted message to send
* \return [bool] Returns true if the message was encrypted, false if key-cache is empty
*/
HKDS_EXPORT_API bool hkds_client_encrypt_authenticate_message(hkds_client_state* state, const uint8_t* plaintext, const uint8_t* data, size_t datalen, uint8_t* ciphertext);

/**
* \brief Initialize the state with the secret key and nonce
*
* \param state [struct] The function state
* \param token [const][array] The secret token key array
*/
HKDS_EXPORT_API void hkds_client_generate_cache(hkds_client_state* state, const uint8_t* token);

/**
* \brief Initialize the state with the embedded device key and device identity
*
* \param state [struct] The function state
* \param edk [const][array] The embedded device key array
* \param did [const][array] The devices unique identity string
*/
HKDS_EXPORT_API void hkds_client_initialize_state(hkds_client_state* state, const uint8_t* edk, const uint8_t* did);

#endif
