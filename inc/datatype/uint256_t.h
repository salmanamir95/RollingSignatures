#ifndef UINT256_H
#define UINT256_H

#include "pkcertchain_config.h"


#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include "util/To_BO_BE_Pimitives.h"
#include "util/To_BO_Def_Primitives.h"
#include "datatype/OpStatus.h"
/* Force aggressive inlining */
#define U256_INLINE static inline __attribute__((always_inline))

/* 4-byte alignment (32-bit) */
typedef struct __attribute__((aligned(4))) {
    uint64_t w[4];   /* little-endian word order */
} uint256;


/* ---------- Constructors ---------- */

U256_INLINE void uint256_zero(uint256 *u)
{
    u->w[0] = 0;
    u->w[1] = 0;
    u->w[2] = 0;
    u->w[3] = 0;
}

U256_INLINE void uint256_from_u64(uint256 *u, uint64_t v)
{
    u->w[0] = v;
    u->w[1] = 0;
    u->w[2] = 0;
    u->w[3] = 0;
}


/* ---------- Comparison ---------- */

U256_INLINE bool uint256_equal(const uint256 *a,
                               const uint256 *b)
{
    /* branchless */
    return ((a->w[0] ^ b->w[0]) |
            (a->w[1] ^ b->w[1]) |
            (a->w[2] ^ b->w[2]) |
            (a->w[3] ^ b->w[3])) == 0;
}

U256_INLINE bool uint256_not_equal(const uint256 *a,
                                   const uint256 *b)
{
    return !uint256_equal(a, b);
}


/* ---------- Bit Access ---------- */

U256_INLINE bool uint256_get_bit(const uint256 *u, unsigned bit)
{
    return (u->w[bit >> 6] >> (bit & 63)) & 1;
}

U256_INLINE void uint256_set_bit(uint256 *u,
                                 unsigned bit,
                                 bool val)
{
    uint64_t mask = 1ULL << (bit & 63);

    if (val)
        u->w[bit >> 6] |= mask;
    else
        u->w[bit >> 6] &= ~mask;
}


/* ---------- Copy ---------- */

U256_INLINE void uint256_copy(uint256 *dst,
                              const uint256 *src)
{
    /* lets compiler vectorize */
    memcpy(dst, src, sizeof(uint256));
}


#define UINT256_SIZE 32  // 4 * 8 bytes

U256_INLINE OpStatus_t uint256_serialize_be(const uint256 *u, uint8_t *out, size_t out_size)
{
    if (!u || !out) return OP_NULL_PTR;
    if (out_size < UINT256_SIZE) return OP_BUF_TOO_SMALL;
    for (int i = 0; i < 4; ++i) {
        serialize_u64_be(u->w[i], out + (i * 8));
    }
    return OP_SUCCESS;
}

U256_INLINE OpStatus_t uint256_deserialize_be(const uint8_t *in, size_t in_size, uint256 *u)
{
    if (!u || !in) return OP_NULL_PTR;
    if (in_size < UINT256_SIZE) return OP_BUF_TOO_SMALL;
    for (int i = 0; i < 4; ++i) {
        deserialize_u64_be(in + (i * 8), &u->w[i], sizeof(uint64_t));
    }
    return OP_SUCCESS;
}

U256_INLINE OpStatus_t uint256_serialize_two_be(const uint256 *a, const uint256 *b, uint8_t *out, size_t out_size)
{
    if (!a || !b || !out) return OP_NULL_PTR;
    if (out_size < (UINT256_SIZE * 2)) return OP_BUF_TOO_SMALL;
    if (uint256_serialize_be(a, out, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_serialize_be(b, out + UINT256_SIZE, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}


#endif
