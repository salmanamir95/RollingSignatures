#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "datatype/OpStatus.h"
#include "datatype/uint256_t.h"
#include "datatype/uint512.h"
#include "util/SignUtils.h"

// Use a macro for signature size if not defined elsewhere
#ifndef UINT512_SIZE
#define UINT512_SIZE 64
#endif

// We define PACKET_INLINE similar to CERT_INLINE for high performance
#define PACKET_INLINE static inline __attribute__((always_inline))

/*
 * Concept: Packet = Payload || Signature
 * The packet consists of a variable-length data payload followed immediately
 * by a 64-byte Ed25519 signature over that payload.
 */

/**
 * @brief Signs a payload using Ed25519 and outputs the signature.
 */
PACKET_INLINE OpStatus_t packet_sign(const uint8_t *payload, size_t payload_len, const uint256 *priv_key, uint512 *out_sig)
{
    if (!payload || !priv_key || !out_sig) return OP_NULL_PTR;
    
    return sign_buffer_ed25519(payload, payload_len, priv_key, out_sig);
}

/**
 * @brief Verifies a payload against an Ed25519 signature and public key.
 */
PACKET_INLINE OpStatus_t packet_verify(const uint8_t *payload, size_t payload_len, const uint512 *sig, const uint256 *pub_key)
{
    if (!payload || !sig || !pub_key) return OP_NULL_PTR;
    
    return verify_buffer_ed25519_status(payload, payload_len, pub_key, sig);
}

/**
 * @brief Serializes a payload and its signature into a single `Payload || Signature` buffer.
 */
PACKET_INLINE OpStatus_t packet_serialize(const uint8_t *payload, size_t payload_len, const uint512 *sig, uint8_t *out_buffer, size_t out_size)
{
    if (!payload || !sig || !out_buffer) return OP_NULL_PTR;
    
    // Ensure the output buffer is large enough for the payload + 64-byte signature
    if (out_size < (payload_len + UINT512_SIZE)) return OP_BUF_TOO_SMALL;

    // 1. Copy payload bytes
    memcpy(out_buffer, payload, payload_len);
    
    // 2. Append Signature
    // Following uint256_serialize_be pattern, assuming uint512_serialize_be exists
    return uint512_serialize_be(sig, out_buffer + payload_len, UINT512_SIZE);
}

/**
 * @brief Deserializes a `Payload || Signature` buffer back into separate payload and signature.
 */
PACKET_INLINE OpStatus_t packet_deserialize(const uint8_t *in_buffer, size_t in_size, size_t payload_len, uint8_t *out_payload, uint512 *out_sig)
{
    if (!in_buffer || !out_payload || !out_sig) return OP_NULL_PTR;
    
    // The input bounds must be at least the expected payload length + 64 bytes
    if (in_size < (payload_len + UINT512_SIZE)) return OP_BUF_TOO_SMALL;
    
    // 1. Extract payload bytes
    memcpy(out_payload, in_buffer, payload_len);
    
    // 2. Extract signature
    return uint512_deserialize_be(in_buffer + payload_len, UINT512_SIZE, out_sig);
}

#endif // PACKET_H
