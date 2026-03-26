#ifndef SEED_UTIL_H
#define SEED_UTIL_H

#include "pkcertchain_config.h"
#include "blockchain/certificate.h"
#include "util/utilities.h"
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

UTIL_INLINE OpStatus_t mini_pow_seed_gen(const certificate *new_cert, const uint256 *lastBlockHash,
                                         const uint32_t *sessionId, const uint32_t *challengeID, uint256 *seed)
{
    if (!new_cert || !lastBlockHash || !sessionId || !challengeID || !seed)
        return OP_INVALID_INPUT;

    uint8_t *buf = (uint8_t *)malloc(CERT_SIZE + UINT256_SIZE + UINT32_SIZE + UINT32_SIZE);
    if (!buf) return OP_INVALID_STATE;

    OpStatus_t status = cert_serialize(new_cert, buf, CERT_SIZE);
    if (status != OP_SUCCESS)
    {
        free(buf);
        return status;
    }
    status = uint256_serialize_be(lastBlockHash, buf + CERT_SIZE, UINT256_SIZE);
    if (status != OP_SUCCESS)
    {
        free(buf);
        return status;
    }
    serialize_u32_be(*sessionId, buf + CERT_SIZE + UINT256_SIZE);
    serialize_u32_be(*challengeID, buf + CERT_SIZE + UINT256_SIZE + UINT32_SIZE);

    hash256_buffer(buf, CERT_SIZE + UINT256_SIZE + UINT32_SIZE + UINT32_SIZE, seed);
    free(buf);
    return OP_SUCCESS;
}


UTIL_INLINE OpStatus_t mini_pow_csprng(const uint256* seed, const uint32_t* iteration, uint16_t* out_val)
{
    if (!seed || !iteration || !out_val) return OP_INVALID_INPUT;

    uint8_t iterbuf[UINT32_SIZE];
    serialize_u32_be(*iteration, iterbuf); 
    uint8_t seedbuf[UINT256_SIZE];
    uint256_serialize_be(seed, seedbuf, UINT256_SIZE);

    unsigned char result[32]; // SHA256 size
    unsigned int result_len = 0;
    
    if (HMAC(EVP_sha256(), seedbuf, UINT256_SIZE, iterbuf, UINT32_SIZE, result, &result_len) == NULL) {
        return OP_INVALID_STATE;
    }

    uint32_t temp = ((uint32_t)result[0] << 24) | ((uint32_t)result[1] << 16) | ((uint32_t)result[2] << 8) | result[3];

    // Return lower 16 bits
    *out_val = (uint16_t)(temp & 0xFFFF);

    return OP_SUCCESS;
}


#endif