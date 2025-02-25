# HKDS Protocol Project Documentation

## Introduction

The HKDS Protocol Project implements a Hierarchical Key Derivation System (HKDS) designed to provide a robust and secure mechanism for key management and token exchange between client devices and a transaction processing server. Leveraging cryptographic primitives standardized by NIST (including SHA-3, SHAKE, and KMAC), the HKDS protocol is well-suited for high-security environments such as point-of-sale (POS) systems.
See the documentation at: https://qrcs-corp.github.io/SKDP/

## HKDS Protocol Overview

The HKDS protocol is built upon a hierarchical structure for key derivation. Its main components include:

- **Master Key Set (MDK):** Comprised of a Base Derivation Key (BDK), a Secret Token Key (STK), and a Key Identity (KID).
- **Key Serial Number (KSN):** A unique identifier for each client that encapsulates the device identity (DID) and a token counter.
- **Embedded Device Key (EDK):** Derived from the device's unique identity and the BDK, this key is used to generate the Transaction Key Cache (TKC).
- **Transaction Key Cache (TKC):** A set of keys generated from the decrypted token and the EDK. These keys are used for encrypting and authenticating messages.

The protocol employs:
- **SHAKE Functions:** Acting as the primary pseudo-random function (PRF) for generating key streams.
- **KMAC Functions:** Providing message authentication to ensure the integrity of encrypted data.
- **Token Exchange:** A secure process where the server encrypts a token using the STK and a custom token string, and the client decrypts the token to derive the transaction keys.

## HKDS Test Project

The HKDS Test Project is an extensive suite of tests designed to validate both the functionality and performance of the HKDS implementation. Key test categories include:

- **Cycle Tests:** Verify full protocol interactions between the server and client.
- **Known-Answer Tests (KAT):** Compare outputs of encryption, decryption, and key derivation operations against pre-computed expected results.
- **Authenticated Encryption Tests (KATAE):** Confirm that the authenticated encryption process produces the correct ciphertext and MAC tag.
- **Monte Carlo Tests:** Run repeated cycles to verify the robustness and consistency of the implementation.
- **Stress Tests:** Continuously execute full protocol cycles to assess the system's stability under load.
- **SIMD/Parallel Tests:** Validate that vectorized implementations (using SIMD instructions) produce equivalent results to the sequential versions.
- **Benchmark Tests:** Measure the timing performance of the cryptographic primitives and overall protocol operations.

## Project Structure

The project is organized into several modules:

- **Client Module (`hkds_client.h`/`.c`):** Contains functions for key management, message encryption, and token handling on the client side.
- **Server Module (`hkds_server.h`/`.c`):** Implements key derivation, token generation, and message decryption for the server.
- **Configuration Module (`hkds_config.h`):** Defines protocol parameters, key sizes, and mode settings.
- **Queue Module (`hkds_queue.h`/`.c`):** Implements message queuing for asynchronous operations.
- **Benchmark Module (`hkds_benchmark.h`/`.c`):** Provides performance benchmarking for cryptographic primitives and protocol operations.
- **Test Module (`hkds_test.h`/`.c`):** Contains comprehensive tests for functional correctness and performance.

## Conclusion

Together, these modules form a complete solution for secure key management and message processing in transactional systems. The HKDS protocol, with its rigorous testing and performance benchmarks, ensures both security and operational efficiency in high-stakes environments. This documentation serves as a guide for understanding, using, and extending the HKDS protocol and its accompanying test suite.

---

QRCS-PL private License. See license file for details.  
Software is copyrighted and SKDP is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
All rights reserved by QRCS Corp. 2025.
