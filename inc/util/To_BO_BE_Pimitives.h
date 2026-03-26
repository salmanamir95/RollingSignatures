#ifndef UTIL_TO_BO_BE_PRIMITIVES_H
#define UTIL_TO_BO_BE_PRIMITIVES_H

#include "pkcertchain_config.h"


#include <endian.h>
#include <stdint.h>
#include <string.h>

static inline void serialize_u8(uint8_t v, uint8_t *out)
{
    out[0] = v;
}

static inline void serialize_u16_be(uint16_t v, uint8_t *out)
{
    uint16_t be = htobe16(v);
    memcpy(out, &be, 2);
}

static inline void serialize_u32_be(uint32_t v, uint8_t *out)
{
    uint32_t be = htobe32(v);
    memcpy(out, &be, 4);
}

static inline void serialize_u64_be(uint64_t v, uint8_t *out)
{
    uint64_t be = htobe64(v);
    memcpy(out, &be, 8);
}

#endif // UTIL_TO_BO_BE_PRIMITIVES_H
