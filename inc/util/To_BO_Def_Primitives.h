#ifndef UTIL_TO_BO_DEF_PRIMITIVES_H
#define UTIL_TO_BO_DEF_PRIMITIVES_H

#include "pkcertchain_config.h"


#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <endian.h>

/*
 * Default-endianness (native) serialization helpers.
 * These perform byte-for-byte copies in host order.
 */
static inline void serialize_def(const void *value, size_t size, uint8_t *out)
{
    memcpy(out, value, size);
}

static inline void deserialize_def(const uint8_t *in, void *value, size_t size)
{
    memcpy(value, in, size);
}

static inline void deserialize_u8_def(const uint8_t *in, uint8_t *out, size_t size)
{
    (void)size;
    memcpy(out, in, sizeof(uint8_t));
}

static inline void deserialize_u16_def(const uint8_t *in, uint16_t *out, size_t size)
{
    (void)size;
    uint16_t v;
    memcpy(&v, in, sizeof(uint16_t));
    *out = le16toh(v);
}

static inline void deserialize_u32_def(const uint8_t *in, uint32_t *out, size_t size)
{
    (void)size;
    uint32_t v;
    memcpy(&v, in, sizeof(uint32_t));
    *out = le32toh(v);
}

static inline void deserialize_u64_def(const uint8_t *in, uint64_t *out, size_t size)
{
    (void)size;
    uint64_t v;
    memcpy(&v, in, sizeof(uint64_t));
    *out = le64toh(v);
}

static inline void deserialize_u16_be(const uint8_t *in, uint16_t *out, size_t size)
{
    (void)size;
    uint16_t v;
    memcpy(&v, in, sizeof(uint16_t));
    *out = be16toh(v);
}

static inline void deserialize_u32_be(const uint8_t *in, uint32_t *out, size_t size)
{
    (void)size;
    uint32_t v;
    memcpy(&v, in, sizeof(uint32_t));
    *out = be32toh(v);
}

static inline void deserialize_u64_be(const uint8_t *in, uint64_t *out, size_t size)
{
    (void)size;
    uint64_t v;
    memcpy(&v, in, sizeof(uint64_t));
    *out = be64toh(v);
}

#endif // UTIL_TO_BO_DEF_PRIMITIVES_H
