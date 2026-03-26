#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include "pkcertchain_config.h"


#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "datatype/uint256_t.h"
#include "datatype/uint512.h"
#include "util/Size_Offsets.h"
#include "util/To_BO_BE_Pimitives.h"
#include "util/To_BO_Def_Primitives.h"
#include "util/SignUtils.h"
#include "datatype/OpStatus.h"


#define CERT_INLINE static inline __attribute__((always_inline))

/*
 * Certificate structure:
 * - 4-byte aligned (32-bit alignment)
 * - Serialized size is 68 bytes
 * - In-memory size is typically 72 bytes on 64-bit due to uint64 alignment
 */

typedef struct __attribute__((aligned(4))) {
    uint256 pubSignKey;    // 32 bytes
    uint256 pubEncKey;     // 32 bytes
    uint8_t  id;           // 1 byte node id
    uint8_t  reserved[3]; // padding 3 byte
} certificate;

CERT_INLINE void cert_init(certificate * cert){
    uint256_zero(&cert->pubEncKey);
    uint256_zero(&cert->pubSignKey);
    cert->id = 0;
    memset(cert->reserved, 0, sizeof(cert->reserved));
}

CERT_INLINE const uint256* cert_get_pubSignKey_ptr(const certificate *cert) {
    return &cert->pubSignKey;
}


CERT_INLINE const uint256* cert_get_pubEncKey(const certificate * cert){
    return &cert->pubEncKey;
}

CERT_INLINE const uint8_t cert_get_id(const certificate * cert){
    return cert->id;
}

CERT_INLINE void cert_set_pubSignKey(certificate * cert, const uint256 * key){
    cert->pubSignKey = *key;
}

CERT_INLINE void cert_set_pubEncKey(certificate * cert, const uint256 * key){
    cert->pubEncKey = *key;
}

CERT_INLINE void cert_set_id(certificate * cert, uint8_t id){
    cert->id = id;
}

CERT_INLINE void cert_copy(certificate * dst, const certificate * src){
    uint256_copy(&dst->pubSignKey, &src->pubSignKey);
    uint256_copy(&dst->pubEncKey, &src->pubEncKey);
    dst->id = src->id;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}

CERT_INLINE OpStatus_t cert_serialize(const certificate *cert, uint8_t *out, size_t out_size)
{
    if (!cert || !out) return OP_NULL_PTR;
    if (out_size < CERT_SIZE) return OP_BUF_TOO_SMALL;

    if (uint256_serialize_be(&cert->pubSignKey, out, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_serialize_be(&cert->pubEncKey, out + UINT256_SIZE, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    serialize_u8(cert->id, out + (UINT256_SIZE * 2));
    memcpy(out + (UINT256_SIZE * 2) + 1, cert->reserved, sizeof(cert->reserved));
    return OP_SUCCESS;
}

CERT_INLINE OpStatus_t cert_deserialize(const uint8_t *in, size_t in_size, certificate *cert)
{
    if (!cert || !in) return OP_NULL_PTR;
    if (in_size < CERT_SIZE) return OP_BUF_TOO_SMALL;

    if (uint256_deserialize_be(in, UINT256_SIZE, &cert->pubSignKey) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_deserialize_be(in + UINT256_SIZE, UINT256_SIZE, &cert->pubEncKey) != OP_SUCCESS) return OP_INVALID_INPUT;
    deserialize_u8_def(in + (UINT256_SIZE * 2), &cert->id, sizeof(uint8_t));
    memcpy(cert->reserved, in + (UINT256_SIZE * 2) + 1, sizeof(cert->reserved));
    return OP_SUCCESS;
}

CERT_INLINE OpStatus_t hash_certificate(const certificate *cert, uint256 *out)
{
    if (!cert || !out) return OP_NULL_PTR;

    uint8_t buf[CERT_SIZE];
    OpStatus_t st = cert_serialize(cert, buf, sizeof(buf));
    if (st != OP_SUCCESS) return st;

    hash256_buffer(buf, sizeof(buf), out);
    return OP_SUCCESS;
}

CERT_INLINE OpStatus_t cert_sign(const certificate *cert, const uint256 *priv_key, uint512 *out_sig)
{
    if (!cert || !priv_key || !out_sig) return OP_NULL_PTR;

    uint8_t buf[CERT_SIZE];
    OpStatus_t st = cert_serialize(cert, buf, sizeof(buf));
    if (st != OP_SUCCESS) return st;

    return sign_buffer_ed25519(buf, sizeof(buf), priv_key, out_sig);
}


#endif // CERTIFICATE_H
