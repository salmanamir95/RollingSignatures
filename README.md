# HMAC Multihop Routing Protocol

A secure, high-performance multihop routing system using **in-place evolving HMACs** to guarantee payload and route integrity. Designed for both RREQ (growing path vector) and RREP (fixed path vector) contexts.

## Overview
Unlike heavy asymmetric blockchain-style sliding signatures, this protocol optimizes routing bandwidth and node processing time using ultra-fast SHA-256 HMAC derivations. A new symmetric key is natively calculated strictly on-the-fly (`Ki = SHA256(K_{i-1} || NodeID_i)`) ensuring strong forward-authenticity and deep path tracking.

## Quick Start
### Prerequisites
- CMake >= 3.14
- OpenSSL (libcrypto / libssl)
- C11 Compiler

### Build
```bash
cmake -S . -B build
cmake --build build
```

### Run Multi-Hop Test Simulation
```bash
cd build
./test_hmac_routing
```

## Documentation
- [Architecture Details](docs/architecture.md): The structural integrity and key mechanics of the multihop protocol.
- [Current Implementation](docs/currentImplementation.md): Notes strictly on the current C protocol execution behavior.
