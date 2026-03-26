#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "datatype/OpStatus.h"
#include "datatype/uint256_t.h"
#include "datatype/uint512.h"
#include "util/SignUtils.h"
#include "certifiicate/certificate.h"

#ifndef UINT512_SIZE
#define UINT512_SIZE 64
#endif

#define PACKET_INLINE static inline __attribute__((always_inline))

/*
 * Concept: Packet = Payload || Signature
 * The signature is generated over (Payload || Certificate) using Ed25519.
 */

/**
 * @brief Signs a payload and certificate using Ed25519 and outputs the signature.
 */
PACKET_INLINE OpStatus_t packet_sign(const uint8_t *payload, size_t payload_len, const certificate *cert, const uint256 *priv_key, uint512 *out_sig)
{
    if (!payload || !cert || !priv_key || !out_sig) return OP_NULL_PTR;
    
    // Allocate contiguous buffer for payload || certificate
    size_t combined_len = payload_len + CERT_SIZE;
    uint8_t *combined = (uint8_t *)malloc(combined_len);
    if (!combined) return OP_INVALID_STATE; // memory error

    memcpy(combined, payload, payload_len);
    OpStatus_t st = cert_serialize(cert, combined + payload_len, CERT_SIZE);
    if (st != OP_SUCCESS) {
        free(combined);
        return st;
    }

    st = sign_buffer_ed25519(combined, combined_len, priv_key, out_sig);
    free(combined);
    return st;
}

/**
 * @brief Verifies a payload + certificate against an Ed25519 signature and public key.
 */
PACKET_INLINE OpStatus_t packet_verify(const uint8_t *payload, size_t payload_len, const certificate *cert, const uint512 *sig, const uint256 *pub_key)
{
    if (!payload || !cert || !sig || !pub_key) return OP_NULL_PTR;
    
    // Allocate contiguous buffer for payload || certificate
    size_t combined_len = payload_len + CERT_SIZE;
    uint8_t *combined = (uint8_t *)malloc(combined_len);
    if (!combined) return OP_INVALID_STATE;

    memcpy(combined, payload, payload_len);
    OpStatus_t st = cert_serialize(cert, combined + payload_len, CERT_SIZE);
    if (st != OP_SUCCESS) {
        free(combined);
        return OP_SIGN_VERIFIED_FALSE;
    }

    st = verify_buffer_ed25519_status(combined, combined_len, pub_key, sig);
    free(combined);
    return st;
}

/**
 * @brief Serializes a payload and its signature into a single `Payload || Signature` buffer.
 */
PACKET_INLINE OpStatus_t packet_serialize(const uint8_t *payload, size_t payload_len, const uint512 *sig, uint8_t *out_buffer, size_t out_size)
{
    if (!payload || !sig || !out_buffer) return OP_NULL_PTR;
    
    if (out_size < (payload_len + UINT512_SIZE)) return OP_BUF_TOO_SMALL;

    memcpy(out_buffer, payload, payload_len);
    return uint512_serialize_be(sig, out_buffer + payload_len, UINT512_SIZE);
}

/**
 * @brief Deserializes a `Payload || Signature` buffer back into separate payload and signature.
 */
PACKET_INLINE OpStatus_t packet_deserialize(const uint8_t *in_buffer, size_t in_size, size_t payload_len, uint8_t *out_payload, uint512 *out_sig)
{
    if (!in_buffer || !out_payload || !out_sig) return OP_NULL_PTR;
    
    if (in_size < (payload_len + UINT512_SIZE)) return OP_BUF_TOO_SMALL;
    
    memcpy(out_payload, in_buffer, payload_len);
    return uint512_deserialize_be(in_buffer + payload_len, UINT512_SIZE, out_sig);
}

#endif // PACKET_H
