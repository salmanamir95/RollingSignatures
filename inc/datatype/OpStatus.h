#ifndef OP_STATUS_H
#define OP_STATUS_H

#include "pkcertchain_config.h"



#include <stdint.h>

typedef uint8_t OpStatus_t;

#define OP_NULL_PTR      0
#define OP_BUF_TOO_SMALL 1
#define OP_INVALID_INPUT 2
#define OP_SUCCESS       3
#define OP_NEEDS_PRIVILEGE 4
#define OP_SIGN_VERIFIED_FALSE 5
#define OP_SIGN_VERIFIED_TRUE  6
#define OP_INVALID_STATE 7


#endif // OP_STATUS_H
