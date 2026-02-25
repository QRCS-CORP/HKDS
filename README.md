# HKDS — Hierarchical Key Derivation System

[![Build Status](https://github.com/QRCS-CORP/HKDS/actions/workflows/build.yml/badge.svg)](https://github.com/QRCS-CORP/HKDS/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/HKDS/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/HKDS/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/hkds/badge)](https://www.codefactor.io/repository/github/qrcs-corp/hkds)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![Security Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=PCI%20DSS&color=blue)](https://listings.pcisecuritystandards.org/pci_security/)
[![Target Industry](https://img.shields.io/static/v1?label=Target%20Industry&message=Financial&color=brightgreen)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](https://github.com/QRCS-CORP/HKDS/security/policy)
[![License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/HKDS/blob/main/License.txt)
[![Docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/HKDS/)
[![Release](https://img.shields.io/github/v/release/QRCS-CORP/HKDS)](https://github.com/QRCS-CORP/HKDS/releases/tag/2025-05-27)
[![Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/HKDS.svg)](https://github.com/QRCS-CORP/HKDS/releases)

**A stateless hierarchical key derivation and token exchange protocol for high-security point-of-sale and transactional systems, built on NIST-standardised post-quantum primitives (SHA-3/SHAKE/KMAC).**

---

## Table of Contents

- [Overview](#overview)
- [Protocol Design](#protocol-design)
- [Key Derivation Chain](#key-derivation-chain)
- [Test Suite](#test-suite)
- [Project Structure](#project-structure)
- [Building](#building)
  - [Prerequisites](#prerequisites)
  - [Windows (MSVC)](#windows-msvc)
  - [macOS / Ubuntu (Eclipse)](#macos--ubuntu-eclipse)
  - [Compiler Flag Reference](#compiler-flag-reference)
- [Documentation](#documentation)
- [License](#license)

---

## Overview

HKDS is a **Hierarchical Key Derivation System** that provides secure key management and token exchange between constrained client devices (e.g., POS terminals) and a centralised transaction processing server. The protocol is designed for environments where devices operate with limited connectivity, where each transaction must use a unique key, and where compromise of any single device must not expose the wider device fleet.

HKDS is built exclusively on primitives standardised by NIST:

| Primitive | Role |
|-----------|------|
| **SHAKE-128 / SHAKE-256 / SHAKE-512** | Pseudorandom function (PRF) for key stream generation |
| **KMAC-128 / KMAC-256 / KMAC-512** | Message authentication (NIST SP 800-185) |
| **SHA-3** | Supporting hash operations |

The SHAKE variant is selected at compile time, scaling security levels across the entire key hierarchy from root material through to transaction keys.

---

## Protocol Design

HKDS uses a **stateless server architecture** inspired by DUKPT. The server re-derives any transaction key on demand from the received Key Serial Number (KSN) and the master key set — no per-device state is stored server-side. This makes the protocol suitable for load-balanced and redundant server deployments.

### Core Components

| Component | Description |
|-----------|-------------|
| **Master Key Set (MDK)** | Held by the server only. Contains the Base Derivation Key (BDK), Secret Token Key (STK), and a Key Identity (KID). |
| **Key Serial Number (KSN)** | 16-byte identifier per client: Device Identity (DID, 12 bytes) \|\| transaction counter (4 bytes, big-endian). Transmitted with every message. |
| **Embedded Device Key (EDK)** | `SHAKE(DID ‖ BDK)` — device-unique, provisioned into the client. Never changes for the device lifetime. |
| **Epoch Token (tok)** | `SHAKE(CTOK ‖ STK)` — server-derived, device- and epoch-unique. Delivered encrypted to the client each epoch. |
| **Transaction Key Cache (TKC)** | `SHAKE(tok ‖ EDK)` — generates a batch of unique transaction keys. Each key is used once then erased. |

### Transaction Key Uniqueness

Every transaction key is uniquely determined by the combination of:
- **Device identity** (DID embedded in EDK and the epoch customisation string)
- **Epoch index** (`counter / CACHE_SIZE`) — changes the epoch token `tok`, producing a completely independent key cache
- **Cache slot** (`counter % CACHE_SIZE`) — selects a non-overlapping slice of the epoch keystream

The 32-bit KSN counter is the nonce of the system and is the sole authoritative source of per-message uniqueness. The server always reads the current counter directly from the KSN supplied with each received packet.

### Token Exchange

The server delivers each epoch token encrypted and authenticated:
```
CTOK  = BE32(counter / CACHE_SIZE) ‖ algorithm_name ‖ DID
tok   = SHAKE(CTOK ‖ STK)
ks    = SHAKE(CTOK ‖ EDK)
etok  = ks XOR tok
mac   = KMAC(key=EDK, msg=etok, custom=KSN‖mac_name)
send  = etok ‖ mac
```

The client verifies the KMAC tag using its EDK before decrypting the token. A token exchange is required once per epoch (every `CACHE_SIZE` messages).

---

## Key Derivation Chain
```
BDK ──────────────────────────────────────────────────────► (server only)
 │
 └─ SHAKE(DID ‖ BDK) ──────────────────────────────────► EDK  (on device)
                                                            │
STK ──────────────────────────────────────────────────────►│
 │                                                          │
 └─ SHAKE(CTOK ‖ STK) ────────────────────────────────► tok  (delivered encrypted)
                                                            │
                                        SHAKE(tok ‖ EDK) ──┘
                                                │
                          ┌─────────────────────┴──────────────────────┐
                         TK[0]   TK[1]   TK[2]  ...  TK[CACHE_SIZE-1]
                       (each slot used once and erased)
```

**Security properties of the chain:**
- Compromise of EDK alone is insufficient to compute any TK (STK is also required, held only server-side).
- Compromise of tok exposes only the current epoch's key cache; other epochs are unaffected.
- Past cache slots cannot be recovered — each slot is securely erased immediately after use.

---

## Test Suite

The `HKDSTest` project provides comprehensive validation across seven test categories:

| Test Category | Purpose |
|---------------|---------|
| **Cycle Tests** | Full server ↔ client protocol round-trips, including token exchange and message encrypt/decrypt |
| **Known-Answer Tests (KAT)** | Output verification against pre-computed reference vectors for all key derivation and encryption operations |
| **Authenticated Encryption Tests (KATAE)** | Verification of ciphertext and KMAC tag correctness for the authenticated message path |
| **Monte Carlo Tests** | Repeated cycle execution to verify consistency and detect non-determinism |
| **Stress Tests** | Sustained full-protocol execution to assess stability under load |
| **SIMD / Parallel Tests** | Equivalence checks between vectorised (x8, x64) and scalar implementations |
| **Benchmark Tests** | Timing measurements for cryptographic primitives and complete protocol operations |

---

## Project Structure
```
HKDS/
├── hkds_client.h / .c      Client-side key management, encryption, and token handling
├── hkds_server.h / .c      Server-side key derivation, token generation, and decryption
├── hkds_config.h           Protocol parameters, key sizes, and compile-time mode selection
├── hkds_queue.h / .c       Message queuing for asynchronous batch operations
├── hkds_benchmark.h / .c   Performance benchmarking for primitives and protocol operations
├── hkds_test.h / .c        Functional correctness and performance test suite
└── keccak.h / .c           SHAKE / KMAC / SHA-3 primitive implementations
```

---

## Building

### Prerequisites

| Tool | Minimum Version |
|------|----------------|
| CMake | 3.15 |
| Visual Studio (Windows) | 2022 |
| Clang (macOS) | Via Xcode or Homebrew |
| GCC or Clang (Ubuntu) | Current stable |

---

### Windows (MSVC)

1. Extract the repository so that the `HKDS` library folder and the `HKDSTest` folder are siblings at the same directory level.
2. Open the `HKDSTest` Visual Studio solution.
3. Verify that `HKDSTest` → **Project Properties → C/C++ → General → Additional Include Directories** points to the `HKDS` library folder (`$(SolutionDir)HKDS` by default).
4. Verify that **HKDSTest → References** includes the HKDS library project.
5. Set both the HKDS library and HKDSTest to the **same AVX instruction set** in:  
   **Configuration Properties → C/C++ → All Options → Enable Enhanced Instruction Set**  
   Do this for both **Debug** and **Release** configurations.
6. Right-click the HKDS library and select **Build**.
7. Right-click `HKDSTest`, select **Set as Startup Project**, then run.

> HKDS supports AVX, AVX2, and AVX-512. Both projects must use the same instruction set family.

---

### macOS / Ubuntu (Eclipse)

1. Locate the `Eclipse/Ubuntu` or `Eclipse/MacOS` subfolder in the repository.
2. Copy the `.project`, `.cproject`, and `.settings` files from that subfolder directly into the folder containing the corresponding source files (do this for both the HKDS library and HKDSTest).
3. In Eclipse, create a new **C/C++ → Empty Project** with the same name as each source folder (e.g., `HKDS`, `HKDSTest`). Eclipse will detect and load the copied project settings automatically.
4. Repeat for the `HKDSTest` project, selecting the correct OS-specific files.

> Default project files target AVX2 with AES-NI and RDRAND enabled. Select the Ubuntu or macOS files as appropriate — compiler settings differ between GCC and Clang.

---

### Compiler Flag Reference

#### AVX
```
-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2
```

| Flag | Purpose |
|------|---------|
| `-msse2` | SSE2 baseline (required for x86-64) |
| `-mavx` | 256-bit floating-point and SIMD |
| `-maes` | AES-NI (hardware AES round instructions) |
| `-mpclmul` | PCLMUL carry-less multiply |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | BMI2 bit-manipulation (PEXT/PDEP) |

#### AVX2
```
-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2
```

| Flag | Purpose |
|------|---------|
| `-msse2` | SSE2 baseline |
| `-mavx` | AVX baseline |
| `-mavx2` | 256-bit integer and FP SIMD |
| `-maes` | AES-NI |
| `-mpclmul` | PCLMUL (carry-less multiply for GHASH etc.) |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | BMI2 bit-manipulation |

#### AVX-512
```
-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes
```

| Flag | Purpose |
|------|---------|
| `-msse2` | SSE2 baseline |
| `-mavx` | AVX baseline |
| `-mavx2` | AVX2 baseline (explicit for safety) |
| `-mavx512f` | 512-bit foundation instructions |
| `-mavx512bw` | 512-bit byte/word integer instructions |
| `-mvaes` | Vector AES in 512-bit registers |
| `-mpclmul` | PCLMUL carry-less multiply |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | BMI2 bit-manipulation |
| `-maes` | AES-NI 128-bit rounds |

---

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](https://qrcs-corp.github.io/HKDS/) | Full online help documentation |
| [Summary](https://qrcs-corp.github.io/HKDS/pdf/hkds_summary.pdf) | High-level protocol overview |
| [Protocol Specification](https://qrcs-corp.github.io/HKDS/pdf/hkds_specification.pdf) | Formal protocol description and message formats |
| [Formal Analysis](https://qrcs-corp.github.io/HKDS/pdf/hkds_formal.pdf) | Cryptographic security proofs and formal model |
| [Implementation Analysis](https://qrcs-corp.github.io/HKDS/pdf/hkds_analysis.pdf) | Implementation notes and design rationale |
| [Integration Guide](https://qrcs-corp.github.io/HKDS/pdf/hkds_integration.pdf) | Developer integration reference |

---

## License

### Investment and Licensing Inquiries

QRCS is currently seeking a corporate investor for this technology.  
Parties interested in licensing or investment should contact us at **contact@qrcscorp.ca**  
For a full inventory of our products and services, visit [qrcscorp.ca](https://www.qrcscorp.ca).

---

### Patent Notice

One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

---

### QRCS Public Research and Evaluation License (QRCS-PREL), 2025–2026

This repository contains cryptographic reference implementations, test code, and supporting materials published by **Quantum Resistant Cryptographic Solutions Corporation (QRCS)** for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.

All source code and materials in this repository are provided under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**, unless explicitly stated otherwise.

**Permitted use:**
- Public access, non-commercial research, evaluation, and testing

**Not permitted without a separate written commercial agreement:**
- Production deployment or operational use
- Incorporation into any commercial product or service
- Certified or supported builds

The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.

For commercial licensing, supported implementations, or integration inquiries, contact: **licensing@qrcscorp.ca**

---

*Quantum Resistant Cryptographic Solutions Corporation — All rights reserved, 2026.*