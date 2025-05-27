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

#ifndef HKDS_CLIENT_H
#define HKDS_CLIENT_H

#include "hkds_config.h"

/**
 * \file hkds_client.h
 * \brief HKDS client functions and definitions.
 *
 * \details
 * This file contains definitions and function prototypes for the HKDS (Hierarchical Key Derivation System)
 * client. The HKDS protocol uses cryptographic primitives defined by NIST standards (such as SHA-3, SHAKE,
 * and KMAC) to securely exchange tokens and encrypt messages between client devices and a transaction server.
 *
 * The HKDS client module handles the following operations:
 * 
 * - **Client State Management:** Maintains the client state through the \ref hkds_client_state structure,
 *   which includes the Embedded Device Key (EDK), Key Serial Number (KSN), and Transaction Key Cache (TKC).
 *
 * - **Token Exchange and Decryption:** Receives an encrypted token key (ETOK) from the server, verifies its
 *   integrity using a MAC computed via KMAC, and decrypts it to yield a usable token.
 *
 * - **Transaction Key Cache Generation:** Generates a cache of transaction keys derived from the decrypted token
 *   and the client's EDK. These keys are then used for encrypting and authenticating messages.
 *
 * - **Message Encryption and Authentication:** Provides functions to:
 *   - Encrypt messages using a transaction key (via a bitwise XOR operation).
 *   - Encrypt messages and append an authentication tag (MAC) computed using a keyed KMAC function.
 *
 * These functions ensure that client messages remain confidential and authenticated during transmission.
 */

/*! \struct hkds_client_state
 * \brief Contains the HKDS client state.
 *
 * \details
 * This structure holds all state information required by the HKDS client. It includes:
 * 
 * - \c edk: The Embedded Device Key used for cryptographic operations (size defined by \c HKDS_EDK_SIZE).
 * - \c ksn: The Key Serial Number containing the device identity and transaction counter (size defined by \c HKDS_KSN_SIZE).
 * - \c tkc: The Transaction Key Cache, an array of keys (each of size \c HKDS_MESSAGE_SIZE) used for message encryption
 *   and authentication. The total number of keys is defined by \c HKDS_CACHE_SIZE.
 * - \c cache_empty: A boolean flag indicating whether the key cache has been exhausted.
 */
HKDS_EXPORT_API typedef struct
{
    HKDS_SIMD_ALIGN uint8_t edk[HKDS_EDK_SIZE];
    HKDS_SIMD_ALIGN uint8_t ksn[HKDS_KSN_SIZE];
    HKDS_SIMD_ALIGN uint8_t tkc[HKDS_CACHE_SIZE][HKDS_MESSAGE_SIZE];
    bool cache_empty;
} hkds_client_state;

/**
 * \brief Decrypt an encrypted token key received from the server.
 *
 * \details
 * This function decrypts the encrypted token key (ETOK) sent by the server during the token exchange process.
 * The decryption procedure includes the following steps:
 * 
 * - **Customization String Generation:** A token customization string (CTOK) is generated using the transaction
 *   counter (extracted from the KSN), the formal algorithm name, and the device identity.
 * - **MAC Verification:** A Token MAC String (TMS) is derived from the KSN and the MAC function name. Using this
 *   string, a MAC is computed (via KMAC) over the encrypted token, and compared against the appended MAC to verify
 *   the integrity of the token.
 * - **Key-Stream Derivation and Token Decryption:** If the MAC verification succeeds, the CTOK and the client's
 *   Embedded Device Key (EDK) are combined to generate a key-stream (using a SHAKE function). The token is then
 *   decrypted by XORing the encrypted token key with the generated key-stream.
 *
 * \param state [in] Pointer to the HKDS client state structure.
 * \param etok [in] Pointer to the array containing the encrypted token key.
 * \param token [out] Pointer to the output buffer where the decrypted token key will be stored.
 * \return Returns true if the token is successfully decrypted and the MAC verification passes; false otherwise.
 */
HKDS_EXPORT_API bool hkds_client_decrypt_token(hkds_client_state* state, const uint8_t* etok, uint8_t* token);

/**
 * \brief Encrypt a message to be sent to the server.
 *
 * \details
 * This function encrypts a plaintext message by performing the following steps:
 * 
 * - **Transaction Key Extraction:** Retrieves a transaction key from the key cache (TKC) based on the current
 *   transaction counter embedded in the KSN.
 * - **Message Encryption:** Encrypts the plaintext message by applying a bitwise XOR operation with the extracted
 *   transaction key.
 * - **Key Cache Update:** After a key is used for encryption, it is cleared from the cache to maintain forward security.
 *
 * If the key cache is empty, the function returns false, indicating that encryption cannot proceed.
 *
 * \param state [in] Pointer to the HKDS client state structure.
 * \param plaintext [in] Pointer to the plaintext message array.
 * \param ciphertext [out] Pointer to the buffer where the resulting encrypted message (ciphertext) will be stored.
 * \return Returns true if the message is successfully encrypted; false if the key cache is empty.
 */
HKDS_EXPORT_API bool hkds_client_encrypt_message(hkds_client_state* state, const uint8_t* plaintext, uint8_t* ciphertext);

/**
 * \brief Encrypt a message and append an authentication tag.
 *
 * \details
 * This function performs authenticated encryption by executing two sequential operations:
 * 
 * 1. **Message Encryption:** A transaction key is extracted from the key cache and used to encrypt the plaintext
 *    message (via a bitwise XOR operation).
 * 2. **MAC Generation:** A second transaction key is extracted and used to compute a Message Authentication Code (MAC)
 *    using a KMAC function. The MAC is calculated over the encrypted message and any additional data (for example,
 *    the client's IP address) provided as input.
 * 
 * The final output is a concatenation of the ciphertext and the generated MAC authentication tag.
 *
 * \param state [in] Pointer to the HKDS client state structure.
 * \param plaintext [in] Pointer to the plaintext message array.
 * \param data [in] Pointer to an optional additional data array to be included in the MAC computation.
 * \param datalen [in] The length (in bytes) of the additional data array.
 * \param ciphertext [out] Pointer to the buffer where the authenticated encrypted message will be stored.
 * \return Returns true if both encryption and MAC generation are successful; false if the key cache is empty.
 */
HKDS_EXPORT_API bool hkds_client_encrypt_authenticate_message(hkds_client_state* state, const uint8_t* plaintext, const uint8_t* data, size_t datalen, uint8_t* ciphertext);

/**
 * \brief Generate the transaction key cache (TKC) for the client.
 *
 * \details
 * This function generates a new Transaction Key Cache using the provided secret token key and the client's Embedded
 * Device Key (EDK). The steps include:
 * 
 * - **Key Material Combination:** The secret token key is concatenated with the EDK to form a combined key material array.
 * - **Key-Stream Generation:** A SHAKE function is used on the combined key material to produce a pseudo-random stream of bytes.
 * - **Cache Population:** The generated key-stream is segmented into individual transaction keys, which are then stored in the TKC.
 *
 * Upon completion, the client's cache-empty flag is set to false, indicating that valid keys are available for encryption.
 *
 * \param state [in/out] Pointer to the HKDS client state structure.
 * \param token [in] Pointer to the secret token key array used in generating the key cache.
 */
HKDS_EXPORT_API void hkds_client_generate_cache(hkds_client_state* state, const uint8_t* token);

/**
 * \brief Initialize the HKDS client state.
 *
 * \details
 * This function initializes the client state by setting up the Embedded Device Key (EDK) and the device identity.
 * The initialization process involves:
 * 
 * - Copying the provided EDK into the client state.
 * - Setting the Key Serial Number (KSN) with the device's unique identity (DID).
 * - Clearing the Transaction Key Cache (TKC) to remove any previous data.
 * - Marking the key cache as empty until a new cache is generated.
 *
 * \param state [in/out] Pointer to the HKDS client state structure.
 * \param edk [in] Pointer to the Embedded Device Key array.
 * \param did [in] Pointer to the device's unique identity string array.
 */
HKDS_EXPORT_API void hkds_client_initialize_state(hkds_client_state* state, const uint8_t* edk, const uint8_t* did);


#endif
