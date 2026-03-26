# Current Implementation

The repository has been exclusively streamlined to just the HMAC-based routing mechanism, stripping out any legacy signature overhead (like Ed25519 sliding signatures and complex buffer states).

## Directory Structure
- `inc/hmac_routing.h`: Core protocol headers containing all the fast inline logic.
- `src/main.c`: Standard execution entry point hook.
- `tests/test_hmac_routing.c`: Simulation proving tamper-resistance capability.
- `CMakeLists.txt`: Root build file relying seamlessly on OpenSSL.

## Core Protocol API (`inc/hmac_routing.h`)

All algorithms structurally utilize OpenSSL's `EVP_sha256` and `HMAC` standard implementations. The internal algorithms are strictly executed as `inline` for maximum speed.

- `derive_key()`: Implementation of `Ki = H(K{i-1} || NodeID_i)`.
- `compute_hmac()`: Hashes the unified block of `payload || path_vector || nonce`.

### The Three Operational States
1. **`create_packet(pkt, payload, payload_len, k0, nonce)`**: 
   Transforms standard data payload into a routed `RoutingPacket` structural context initialized logically with a nonce and the mathematical master secret `K0`.
2. **`forward_packet(pkt, node_id, k_prev, k_out)`**: 
   The execution workhorse. Operates the verification algorithm, path appending memory, derivation, and the rapid in-place HMAC overwrite in constant time locally. Returns `bool` explicitly indicating incoming mathematical authenticity.
3. **`verify_packet(pkt, k0)`**:
   Run uniquely by the destination to sequentially unpack the entire mathematical key chain and confirm structurally absolute state integrity. Returns `bool`.

## Simulation Testing Integrity (`tests/test_hmac_routing.c`)
Testing fully simulates a robust native 5-node jump (`11 -> 22 -> 33 -> 44 -> 55`). 

**Tamper Detection Code Path:**
An active tamper verification function is fully provided. It actively targets and manipulates the path vector (modifies Hop 3 from `33` to `99`). The protocol inherently proves that mutating exactly one byte of the identity vector structurally shatters the HMAC cascade stream natively, and firmly correctly rejects the broken mathematical hash state.
