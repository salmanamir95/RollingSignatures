# Multihop HMAC Routing Architecture

## Overview
This architectural design introduces deep cryptographic authentication for multi-hop network routing using rapid symmetric-key hashing instead of heavy asymmetric cryptography constraints. 

## Packet Structure
The standard struct `RoutingPacket` carries only exactly what it natively absolutely needs:
```text
[ Payload ] || [ Path Vector ] || [ HMAC (32 bytes) ] || [ Nonce ]
```
- **Payload**: Fixed or variable size application data constraint.
- **Path Vector**: List of `NodeID`s traversed dynamically (In RREQ this list cascades and expands per router. In RREP it's statically parsed).
- **HMAC**: A single rapid 32-byte hash authentication tag.
- **Nonce**: Anti-replay sequence protection string.

## Core Mechanics

### Key Derivation
The source and ultimate destination share an absolute Master Secret (`K0`).
As the packet jumps from hop to hop `i`, a new per-hop key is dynamically derived mathematically:
```text
Ki = SHA256( K_{i-1} || NodeID_i )
```

### Protocol Security Flow
1. **Source** generates the packet and initiates `HMAC_0` using `K0`.
2. **Intermediate Nodes**:
   - Explicitly verify the incoming HMAC mathematically using `K_{i-1}`.
   - Append their `NodeID` to the expanding path vector.
   - Derive their new native key `K_i`.
   - Re-compute and overwrite the packet's HMAC perfectly in-place over the cascade.
3. **Destination Verification**:
   - Takes `K0` and independently cascades through the sequence of recorded keys explicitly matched to the received path vector keys (`K0` -> `K1` -> `K2` ... -> `Kn`).
   - Recomputes the very final HMAC wrapper natively. 

If an attacker manipulates the payload or path (e.g. injects themselves or modifies a hop), the dynamic derivative key chain structurally collapses mathematically, and the Destination forcefully rejects the packet payload.
