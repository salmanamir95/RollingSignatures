#ifndef SIZE_OFFSETS_H
#define SIZE_OFFSETS_H

#include "pkcertchain_config.h"



// Primitive sizes
#define UINT8_SIZE 1
#define UINT16_SIZE 2
#define UINT32_SIZE 4
#define UINT64_SIZE 8
#define UINT256_SIZE 32
#define UINT512_SIZE 64

// Struct sizes (total serialized size here in serialized we added padings too because for memory alignment and hash consistency)
#define CERT_SIZE (UINT8_SIZE + 2 * UINT256_SIZE + 3 * UINT8_SIZE)                            // 1 + 32 + 32 + 1+1+1 = 68
#define BLOCK_SIZE (CERT_SIZE + 2 * UINT256_SIZE + UINT512_SIZE + 2 * UINT64_SIZE + 4 * UINT8_SIZE) // 68 + 32 + 32 + 64 + 2*8 + 4 = 216
#define PK_CERT_CHAIN_SIZE (100 * BLOCK_SIZE + UINT32_SIZE) // 100 blocks + index (serialized size)

#define MINI_POW_CHALLENGE_SIZE (UINT64_SIZE + 3 * UINT16_SIZE) // 14 bytes
#define MINI_POW_SOLVE_SIZE (3 * UINT16_SIZE + 3 * UINT64_SIZE) // 30 bytes
#define TIER_POW_CHALLENGE_SIZE (UINT256_SIZE + UINT8_SIZE + UINT64_SIZE + 3 * UINT8_SIZE) // 44 bytes
#define TIER_POW_SOLVE_SIZE (UINT64_SIZE + UINT8_SIZE + UINT64_SIZE + 3 * UINT8_SIZE) // 20 bytes

#define MINI_POW_MATRIX_N 10

#endif
