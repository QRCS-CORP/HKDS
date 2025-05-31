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
 * Contact: contact@qrcscorp.ca
 */

#ifndef HKDS_SERVER_H
#define HKDS_SERVER_H

#include "hkds_config.h"

/**
 * \file hkds_server.h
 * \brief This file contains HKDS server definitions.
 *
 * \details
 * This header defines the structures and function prototypes for the HKDS (Hierarchical Key Derivation System)
 * server implementation. The HKDS server is responsible for managing key derivation, token exchange, and secure
 * message processing for client devices. It supports both scalar operations and parallel vectorized operations
 * (using x8 and x64 APIs) for improved performance.
 */

/*! 
 * \struct hkds_master_key
 * \brief Contains the HKDS master key set.
 *
 * \details
 * The master key set is comprised of:
 * - \c bdk: The Base Derivation Key used to derive client embedded keys.
 * - \c stk: The Secret Token Key used to generate device tokens.
 * - \c kid: The Key Identity, which uniquely identifies the master key set.
 */
HKDS_EXPORT_API typedef struct
{
    uint8_t bdk[HKDS_BDK_SIZE];  /*!< The base derivation key */
    uint8_t stk[HKDS_STK_SIZE];  /*!< The secret token key */
    uint8_t kid[HKDS_KID_SIZE];  /*!< The key identity */
} hkds_master_key;

/*!
 * \struct hkds_server_state
 * \brief Contains the HKDS server state.
 *
 * \details
 * This structure represents the state of an HKDS server instance. It includes:
 * - \c ksn: The client's Key Serial Number (KSN).
 * - \c mdk: A pointer to the master key set used for deriving keys.
 * - \c count: The token or transaction count.
 * - \c rate: The output rate for the key derivation function (PRF).
 */
HKDS_EXPORT_API typedef struct
{
    uint8_t ksn[HKDS_KSN_SIZE];  /*!< The key serial number array */
    hkds_master_key* mdk;        /*!< A pointer to the master derivation key */
    size_t count;                /*!< The token count */
    size_t rate;                 /*!< The derivation function's rate */
} hkds_server_state;

/**
 * \brief Decrypt a message sent by the client.
 *
 * \details
 * This function decrypts an encrypted message received from a client by generating a transaction key from
 * the server state and XORing it with the ciphertext.
 *
 * \param state [in,out] Pointer to the HKDS server state.
 * \param ciphertext [in] Pointer to the encrypted message array.
 * \param plaintext [out] Pointer to the buffer where the decrypted message will be stored.
 */
HKDS_EXPORT_API void hkds_server_decrypt_message(hkds_server_state* state, const uint8_t* ciphertext, uint8_t* plaintext);

/**
 * \brief Verify a ciphertext's integrity with a keyed MAC and decrypt the message.
 *
 * \details
 * This function uses KMAC to verify the integrity of an encrypted client message before decrypting it. An optional
 * data array (e.g., the originating client's IP address) can be incorporated into the MAC computation. If the MAC
 * verification succeeds, the ciphertext is decrypted (by XORing with the transaction key) to recover the plaintext.
 * On failure, the plaintext is zeroed.
 *
 * \param state [in,out] Pointer to the HKDS server state.
 * \param ciphertext [in] Pointer to the encrypted message array (which includes an appended MAC tag).
 * \param data [in] Pointer to the additional data array for MAC computation.
 * \param datalen [in] The length in bytes of the additional data array.
 * \param plaintext [out] Pointer to the buffer where the decrypted message will be stored.
 * \return Returns true if the MAC verification is successful and decryption occurs; otherwise, false.
 */
HKDS_EXPORT_API bool hkds_server_decrypt_verify_message(hkds_server_state* state, const uint8_t* ciphertext, const uint8_t* data,
    size_t datalen, uint8_t* plaintext);

/**
 * \brief Encrypt a secret token key to send to the client.
 *
 * \details
 * This function encrypts the secret token key using a derived encryption key based on a custom token string and
 * the client's embedded device key. A MAC is computed over the encrypted token and appended to the output.
 *
 * \param state [in,out] Pointer to the HKDS server state.
 * \param etok [out] Pointer to the buffer where the encrypted token output key array will be stored.
 */
HKDS_EXPORT_API void hkds_server_encrypt_token(hkds_server_state* state, uint8_t* etok);

/**
 * \brief Generate the embedded device key (EDK) for a client.
 *
 * \details
 * The EDK is derived by concatenating the device's unique identity (DID) with the base derivation key (BDK)
 * and then hashing the result using a SHAKE function. The resulting key is used in subsequent token and
 * key derivation operations.
 *
 * \param bdk [in] Pointer to the base derivation key array.
 * \param did [in] Pointer to the device's unique identity string.
 * \param edk [out] Pointer to the buffer where the embedded device key will be stored.
 */
HKDS_EXPORT_API void hkds_server_generate_edk(const uint8_t* bdk, const uint8_t* did, uint8_t* edk);

/**
 * \brief Generate a master key set.
 *
 * \details
 * This function generates a new master key set by invoking a provided random generator function to produce
 * key material. The generated data is split into the base derivation key (BDK) and the secret token key (STK),
 * and the provided key identity (KID) is copied into the master key structure.
 *
 * \param rng_generate [in] Pointer to the random generator function.
 * \param mdk [out] Pointer to the master key set structure where the keys will be stored.
 * \param kid [in] Pointer to the master key identity string.
 */
HKDS_EXPORT_API void hkds_server_generate_mdk(bool (*rng_generate)(uint8_t*, size_t), hkds_master_key* mdk, const uint8_t* kid);

/**
 * \brief Initialize the HKDS server state.
 *
 * \details
 * This function initializes the server state by copying the client's key serial number (KSN), assigning
 * the master key pointer, and initializing the token count and derivation rate.
 *
 * \param state [in,out] Pointer to the HKDS server state.
 * \param mdk [in] Pointer to the master key set.
 * \param ksn [in] Pointer to the client's key serial number.
 */
HKDS_EXPORT_API void hkds_server_initialize_state(hkds_server_state* state, hkds_master_key* mdk, const uint8_t* ksn);

/* --- Parallel Vectorized x8 API --- */

/*!
 * \struct hkds_server_x8_state
 * \brief Contains the HKDS parallel x8 server state.
 *
 * \details
 * This structure is used for vectorized (x8) operations in the server implementation, allowing simultaneous
 * processing of 8 client messages. It includes a 2-dimensional array of client key serial numbers (KSNs) and
 * a pointer to the master key set.
 */
HKDS_EXPORT_API typedef struct
{
    uint8_t ksn[HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE];  /*!< The clients' key serial number 2D array */
    hkds_master_key* mdk;                           /*!< A pointer to the master derivation key structure */
} hkds_server_x8_state;

/**
 * \brief Decrypt a 2-dimensional x8 set of client messages.
 *
 * \details
 * This function decrypts an array of 8 client messages in parallel. For each message, a transaction key is generated,
 * and the ciphertext is decrypted by XORing with the key.
 *
 * \param state [in,out] Pointer to the HKDS x8 server state.
 * \param ciphertext [in] A 2D array of 8 encrypted messages.
 * \param plaintext [out] A 2D array where the decrypted messages will be stored.
 */
HKDS_EXPORT_API void hkds_server_decrypt_message_x8(hkds_server_x8_state* state, 
    const uint8_t ciphertext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE],
    uint8_t plaintext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
 * \brief Verify and decrypt a 2-dimensional x8 set of client messages.
 *
 * \details
 * This function uses KMAC to verify the integrity of 8 client messages in parallel. If the MAC check succeeds,
 * each ciphertext is decrypted and marked as valid; otherwise, the output is zeroed.
 *
 * \param state [in,out] Pointer to the HKDS x8 server state.
 * \param ciphertext [in] A 2D array of 8 encrypted messages (with appended MAC tags).
 * \param data [in] A 2D array of additional data for MAC computation.
 * \param datalen [in] The length (in bytes) of the additional data arrays.
 * \param plaintext [out] A 2D array where the decrypted messages will be stored.
 * \param valid [out] A boolean array indicating the verification status of each message.
 */
HKDS_EXPORT_API void hkds_server_decrypt_verify_message_x8(hkds_server_x8_state* state, 
    const uint8_t ciphertext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE + HKDS_TAG_SIZE],
    const uint8_t data[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], size_t datalen, 
    uint8_t plaintext[HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], 
    bool valid[HKDS_CACHX8_DEPTH]);

/**
 * \brief Encrypt a 2-dimensional x8 set of secret token keys.
 *
 * \details
 * This function encrypts secret token keys for 8 clients in parallel. The output is a 2D array of encrypted
 * token keys with appended MAC tags.
 *
 * \param state [in,out] Pointer to the HKDS x8 server state.
 * \param etok [out] A 2D array where the encrypted token output key arrays will be stored.
 */
HKDS_EXPORT_API void hkds_server_encrypt_token_x8(hkds_server_x8_state* state, 
    uint8_t etok[HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE]);

/**
 * \brief Generate a 2-dimensional x8 set of client embedded device keys.
 *
 * \details
 * This function generates embedded device keys for 8 clients in parallel, based on each client's device
 * identity and the master key set.
 *
 * \param state [in] Pointer to the HKDS x8 server state.
 * \param did [in] A 2D array containing the device unique identity strings for 8 clients.
 * \param edk [out] A 2D array where the embedded device keys will be stored.
 */
HKDS_EXPORT_API void hkds_server_generate_edk_x8(const hkds_server_x8_state* state, 
    uint8_t did[HKDS_CACHX8_DEPTH][HKDS_DID_SIZE],
    uint8_t edk[HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE]);

/**
 * \brief Initialize a 2-dimensional x8 set of server states with client KSNs.
 *
 * \details
 * This function initializes the vectorized server state by copying each client's key serial number (KSN)
 * and assigning the master key set.
 *
 * \param state [in,out] Pointer to the HKDS x8 server state.
 * \param mdk [in] Pointer to the master key set.
 * \param ksn [in] A 2D array containing the client key serial numbers.
 */
HKDS_EXPORT_API void hkds_server_initialize_state_x8(hkds_server_x8_state* state, 
    hkds_master_key* mdk, 
    const uint8_t ksn[HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE]);

#if defined(HKDS_SYSTEM_OPENMP)

/* --- Parallel SIMD Vectorized x64 API --- */

/**
 * \brief Decrypt a 3-dimensional 8x8 set of client messages.
 *
 * \details
 * This function decrypts a 3D array of client messages in parallel using the SIMD vectorized x64 API.
 *
 * \param state [in] An array of HKDS x8 server state structures (one per parallel lane).
 * \param ciphertext [in] A 3D array containing the encrypted messages.
 * \param plaintext [out] A 3D array where the decrypted messages will be stored.
 */
HKDS_EXPORT_API void hkds_server_decrypt_message_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
    const uint8_t ciphertext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE],
    uint8_t plaintext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE]);

/**
 * \brief Verify and decrypt a 3-dimensional 8x8 set of client messages.
 *
 * \details
 * This function verifies the integrity of and decrypts a 3D array of client messages in parallel using
 * the SIMD vectorized x64 API. It processes MAC verification for each message and decrypts valid messages.
 *
 * \param state [in] An array of HKDS x8 server state structures.
 * \param ciphertext [in] A 3D array containing the encrypted messages (with MAC tags).
 * \param data [in] A 3D array containing additional data for MAC verification.
 * \param datalen [in] The length (in bytes) of the additional data arrays.
 * \param plaintext [out] A 3D array where the decrypted messages will be stored.
 * \param valid [out] A 2D boolean array indicating the verification status of each message.
 */
HKDS_EXPORT_API void hkds_server_decrypt_verify_message_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
    const uint8_t ciphertext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_TAG_SIZE + HKDS_MESSAGE_SIZE],
    const uint8_t data[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE], size_t datalen,
    uint8_t plaintext[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_MESSAGE_SIZE],
    bool valid[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH]);

/**
 * \brief Encrypt a 3-dimensional 8x8 set of secret token keys.
 *
 * \details
 * This function encrypts secret token keys for clients in parallel using the SIMD vectorized x64 API.
 *
 * \param state [in] An array of HKDS x8 server state structures.
 * \param etok [out] A 3D array where the encrypted token output key arrays will be stored.
 */
HKDS_EXPORT_API void hkds_server_encrypt_token_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH], 
    uint8_t etok[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_STK_SIZE + HKDS_TAG_SIZE]);

/**
 * \brief Generate a 3-dimensional 8x8 set of client embedded device keys.
 *
 * \details
 * This function generates embedded device keys for a 3D array of clients using the SIMD vectorized x64 API.
 *
 * \param state [in] An array of HKDS x8 server state structures.
 * \param did [in] A 3D array containing the client device identity strings.
 * \param edk [out] A 3D array where the generated embedded device keys will be stored.
 */
HKDS_EXPORT_API void hkds_server_generate_edk_x64(const hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
    uint8_t did[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_DID_SIZE],
    uint8_t edk[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_EDK_SIZE]);

/**
 * \brief Initialize a 3-dimensional 8x8 set of server states with client KSNs.
 *
 * \details
 * This function initializes the server states for multiple parallel lanes by copying client key serial numbers (KSNs)
 * and assigning the corresponding master key sets.
 *
 * \param state [out] An array of HKDS x8 server state structures (one per parallel lane).
 * \param mdk [in] A 3D array of master key sets (one per parallel lane).
 * \param ksn [in] A 3D array containing the client key serial numbers.
 */
HKDS_EXPORT_API void hkds_server_initialize_state_x64(hkds_server_x8_state state[HKDS_PARALLEL_DEPTH],
    hkds_master_key mdk[HKDS_PARALLEL_DEPTH],
    const uint8_t ksn[HKDS_PARALLEL_DEPTH][HKDS_CACHX8_DEPTH][HKDS_KSN_SIZE]);

#endif
#endif
