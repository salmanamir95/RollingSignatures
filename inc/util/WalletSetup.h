#ifndef WALLETSETUP_H
#define WALLETSETUP_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "datatype/OpStatus.h"

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

#define PKCERTCHAIN_BASE_SUBDIR   ".pkcertchain"

/*
 * Check whether ~/.pkcertchain/<network>/wallet exists.
 *
 * Returns:
 *   - true  if setup is needed (missing path)
 *   - false if path exists
 */
UTIL_INLINE bool need_pkcertchain_setup(const char *network_name)
{
    if (!network_name || network_name[0] == '\0') return true;
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return true;

    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s/%s/wallet", home, PKCERTCHAIN_BASE_SUBDIR, network_name) <= 0)
        return true;

    struct stat st;
    if (stat(path, &st) != 0) return true;
    if (!S_ISDIR(st.st_mode)) return true;

    return false;
}

/*
 * Create ~/.pkcertchain/<network>/wallet with mode 700 (non-interactive).
 *
 * Returns:
 *   - OP_SUCCESS on success
 *   - OP_NEEDS_PRIVILEGE if permission is denied
 *   - OP_INVALID_INPUT on failure
 */
UTIL_INLINE OpStatus_t create_wallet(const char *network_name)
{
    if (!network_name || network_name[0] == '\0') return OP_INVALID_INPUT;
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return OP_INVALID_INPUT;

    char base_path[512];
    char wallet_path[512];
    if (snprintf(base_path, sizeof(base_path), "%s/%s/%s", home, PKCERTCHAIN_BASE_SUBDIR, network_name) <= 0)
        return OP_INVALID_INPUT;
    if (snprintf(wallet_path, sizeof(wallet_path), "%s/%s/%s/wallet", home, PKCERTCHAIN_BASE_SUBDIR, network_name) <= 0)
        return OP_INVALID_INPUT;

    // Ensure ~/.pkcertchain exists
    char root_path[512];
    if (snprintf(root_path, sizeof(root_path), "%s/%s", home, PKCERTCHAIN_BASE_SUBDIR) <= 0)
        return OP_INVALID_INPUT;
    if (mkdir(root_path, 0700) != 0 && errno != EEXIST) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    // Create ~/.pkcertchain/<network> if needed
    if (mkdir(base_path, 0700) != 0 && errno != EEXIST) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    // Create ~/.pkcertchain/<network>/wallet if needed
    if (mkdir(wallet_path, 0700) != 0 && errno != EEXIST) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    // Ensure permissions are correct (best-effort)
    if (chmod(wallet_path, 0700) != 0) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    return OP_SUCCESS;
}

/*
 * Ensure wallet directory exists with correct permissions.
 *
 * Returns:
 *   - OP_SUCCESS if already present or created
 *   - OP_NEEDS_PRIVILEGE if permission denied
 *   - OP_INVALID_INPUT on other failures
 */
UTIL_INLINE OpStatus_t ensure_wallet_dir(const char *network_name)
{
    if (!need_pkcertchain_setup(network_name)) return OP_SUCCESS;
    return create_wallet(network_name);
}

#endif // WALLETSETUP_H
