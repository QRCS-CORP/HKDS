# HKDS Protocol Project Documentation

[![Build Status](https://github.com/QRCS-CORP/HKDS/actions/workflows/build.yml/badge.svg)](https://github.com/QRCS-CORP/HKDS/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/HKDS/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/HKDS/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/hkds/badge)](https://www.codefactor.io/repository/github/qrcs-corp/hkds)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/HKDS/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](https://github.com/QRCS-CORP/HKDS/security/policy)
![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/HKDS)

## Introduction

The HKDS Protocol Project implements a Hierarchical Key Derivation System (HKDS) designed to provide a robust and secure mechanism for key management and token exchange between client devices and a transaction processing server. Leveraging cryptographic primitives standardized by NIST (including SHA-3, SHAKE, and KMAC), the HKDS protocol is well-suited for high-security environments such as point-of-sale (POS) systems.

[HKDS Help Documentation](https://qrcs-corp.github.io/HKDS/)  
[HKDS Protocol Specification](https://qrcs-corp.github.io/HKDS/pdf/HKDS_Specification.pdf)  
[HKDS Summary Document](https://qrcs-corp.github.io/HKDS/pdf/HKDS_Technical_Summary.pdf)  

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

## Compilation

### Prerequisites

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang  

### Building HKDS and HKDSTest

#### Windows (MSVC)

Use the Visual Studio solution to create the HKDS library and test project HKDSTest.
Extract the files, and open the HKDSTest project. 
The HKDS library has a default location in a folder parallel to the HKDSTest folder. 
The HKDSTest additional files folder is set to: **$(SolutionDir)HKDS**, if this is not the location of the library files, change it by going to HKDSTest project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **HKDSTest->References** property contains a reference to the HKDS library. HKDS supports every AVX instruction family (AVX/AVX2/AVX-512).   
Set the HKDS library and the HKDSTest project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both HKDS and HKDSTest to the same instruction set in Debug and Release Solution Configurations.  
Compile the HKDS library (right-click and choose build), then set the HKDSTest project as the startup project (right-click Set as Startup Project), and run the project.

#### MacOS / Ubuntu (Eclipse)

The HKDS library and HKDSTest project have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse project files.  Copy those files directly into the folders containing the code files; move the files in the **Eclipse\Ubuntu** or **Eclipse\MacOS** folder to the folder containing the project's header and implementation files, and do the same for the HKDSTest project.  
Create a new project for HKDS, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, ex. HKDSTest.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, but are set to use AVX2, AES-NI, and RDRand by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


## Conclusion

Together, these modules form a complete solution for secure key management and message processing in transactional systems. The HKDS protocol, with its rigorous testing and performance benchmarks, ensures both security and operational efficiency in high-stakes environments. This documentation serves as a guide for understanding, using, and extending the HKDS protocol and its accompanying test suite.

## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact:
john.underhill@protonmail.com  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and HKDS is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
_All rights reserved by QRCS Corp. 2025._
