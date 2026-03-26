#ifndef LINUXUTILS_H
#define LINUXUTILS_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "datatype/OpStatus.h"
#include "datatype/uint256_t.h"
#include "util/EncUtils.h"
#include "util/WalletSetup.h"
#include "util/SignUtils.h"
#include "util/To_BO_BE_Pimitives.h"
#include "util/Size_Offsets.h"

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

#define PKCERTCHAIN_SIGN_PRIV_FILE "sign_priv.key"
#define PKCERTCHAIN_SIGN_PUB_FILE  "sign_pub.key"
#define PKCERTCHAIN_ENC_PRIV_FILE  "enc_priv.key"
#define PKCERTCHAIN_ENC_PUB_FILE   "enc_pub.key"
#define PKCERTCHAIN_CHAIN_STATE_FILE "blockchainState"

#define PKCERTCHAIN_CHAIN_MAGIC "PKCS"
#define PKCERTCHAIN_CHAIN_MAGIC_LEN 4
#define PKCERTCHAIN_CHAIN_VERSION 1

UTIL_INLINE OpStatus_t save_file_0600(const char *path, const uint8_t *buf, size_t len)
{
    if (!path || !buf || len == 0) return OP_INVALID_INPUT;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    size_t written = 0;
    while (written < len) {
        ssize_t rc = write(fd, buf + written, len - written);
        if (rc < 0) {
            int err = errno;
            close(fd);
            if (err == EACCES || err == EPERM) return OP_NEEDS_PRIVILEGE;
            return OP_INVALID_INPUT;
        }
        written += (size_t)rc;
    }

    if (close(fd) != 0) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    return OP_SUCCESS;
}

UTIL_INLINE OpStatus_t read_file_alloc(const char *path, uint8_t **out, size_t *out_len, int *out_errno)
{
    if (!path || !out || !out_len) return OP_INVALID_INPUT;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (out_errno) *out_errno = errno;
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        if (out_errno) *out_errno = errno;
        close(fd);
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }
    if (st.st_size <= 0) {
        close(fd);
        return OP_INVALID_INPUT;
    }

    size_t size = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) {
        close(fd);
        return OP_INVALID_INPUT;
    }

    size_t read_total = 0;
    while (read_total < size) {
        ssize_t rc = read(fd, buf + read_total, size - read_total);
        if (rc <= 0) {
            int err = (rc < 0) ? errno : EIO;
            free(buf);
            close(fd);
            if (out_errno) *out_errno = err;
            if (err == EACCES || err == EPERM) return OP_NEEDS_PRIVILEGE;
            return OP_INVALID_INPUT;
        }
        read_total += (size_t)rc;
    }

    close(fd);
    *out = buf;
    *out_len = size;
    if (out_errno) *out_errno = 0;
    return OP_SUCCESS;
}

UTIL_INLINE OpStatus_t save_keys_to_wallet(const char *network_name,
                                           const char *priv_name,
                                           const char *pub_name,
                                           const uint256 *priv_key,
                                           const uint256 *pub_key,
                                           const char *password,
                                           size_t password_len)
{
    if (!priv_key || !pub_key) return OP_NULL_PTR;
    if (!password || password_len == 0) return OP_INVALID_INPUT;

    if (!network_name || network_name[0] == '\0') return OP_INVALID_INPUT;

    OpStatus_t st = ensure_wallet_dir(network_name);
    if (st != OP_SUCCESS) return st;

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return OP_INVALID_INPUT;

    char priv_path[512];
    char pub_path[512];
    if (snprintf(priv_path, sizeof(priv_path), "%s/%s/%s/wallet/%s",
                 home, PKCERTCHAIN_BASE_SUBDIR, network_name, priv_name) <= 0)
        return OP_INVALID_INPUT;
    if (snprintf(pub_path, sizeof(pub_path), "%s/%s/%s/wallet/%s",
                 home, PKCERTCHAIN_BASE_SUBDIR, network_name, pub_name) <= 0)
        return OP_INVALID_INPUT;

    uint8_t priv_buf[UINT256_SIZE];
    uint8_t pub_buf[UINT256_SIZE];
    if (uint256_serialize_be(priv_key, priv_buf, sizeof(priv_buf)) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_serialize_be(pub_key, pub_buf, sizeof(pub_buf)) != OP_SUCCESS) return OP_INVALID_INPUT;

    uint8_t *enc_priv = NULL;
    size_t enc_priv_len = 0;
    uint8_t *enc_pub = NULL;
    size_t enc_pub_len = 0;

    st = LocalSaveEncrypt(priv_buf, sizeof(priv_buf), password, password_len, &enc_priv, &enc_priv_len);
    if (st != OP_SUCCESS) return st;
    st = LocalSaveEncrypt(pub_buf, sizeof(pub_buf), password, password_len, &enc_pub, &enc_pub_len);
    if (st != OP_SUCCESS) {
        free(enc_priv);
        return st;
    }

    st = save_file_0600(priv_path, enc_priv, enc_priv_len);
    if (st != OP_SUCCESS) {
        free(enc_priv);
        free(enc_pub);
        return st;
    }
    st = save_file_0600(pub_path, enc_pub, enc_pub_len);
    if (st != OP_SUCCESS) return st;

    free(enc_priv);
    free(enc_pub);
    return OP_SUCCESS;
}

/*
 * Save Ed25519 signing keys to ~/.pkcertchain/wallet with 0600 permissions.
 */
UTIL_INLINE OpStatus_t save_sign_keys(const char *network_name,
                                      const uint256 *priv_key, const uint256 *pub_key,
                                      const char *password, size_t password_len)
{
    return save_keys_to_wallet(network_name, PKCERTCHAIN_SIGN_PRIV_FILE, PKCERTCHAIN_SIGN_PUB_FILE,
                               priv_key, pub_key, password, password_len);
}

/*
 * Save X25519 encryption keys to ~/.pkcertchain/wallet with 0600 permissions.
 */
UTIL_INLINE OpStatus_t save_enc_keys(const char *network_name,
                                     const uint256 *priv_key, const uint256 *pub_key,
                                     const char *password, size_t password_len)
{
    return save_keys_to_wallet(network_name, PKCERTCHAIN_ENC_PRIV_FILE, PKCERTCHAIN_ENC_PUB_FILE,
                               priv_key, pub_key, password, password_len);
}

UTIL_INLINE OpStatus_t load_keys_from_wallet(const char *network_name,
                                             const char *priv_name,
                                             const char *pub_name,
                                             const char *password,
                                             size_t password_len,
                                             uint256 *out_priv,
                                             uint256 *out_pub,
                                             bool *out_missing)
{
    if (!priv_name || !pub_name || !password || password_len == 0 || !out_priv || !out_pub) return OP_INVALID_INPUT;
    if (!network_name || network_name[0] == '\0') return OP_INVALID_INPUT;
    if (out_missing) *out_missing = false;

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return OP_INVALID_INPUT;

    char priv_path[512];
    char pub_path[512];
    if (snprintf(priv_path, sizeof(priv_path), "%s/%s/%s/wallet/%s",
                 home, PKCERTCHAIN_BASE_SUBDIR, network_name, priv_name) <= 0)
        return OP_INVALID_INPUT;
    if (snprintf(pub_path, sizeof(pub_path), "%s/%s/%s/wallet/%s",
                 home, PKCERTCHAIN_BASE_SUBDIR, network_name, pub_name) <= 0)
        return OP_INVALID_INPUT;

    uint8_t *enc_priv = NULL;
    size_t enc_priv_len = 0;
    uint8_t *enc_pub = NULL;
    size_t enc_pub_len = 0;
    int err_priv = 0;
    int err_pub = 0;

    OpStatus_t st = read_file_alloc(priv_path, &enc_priv, &enc_priv_len, &err_priv);
    if (st != OP_SUCCESS) {
        if (err_priv == ENOENT || err_priv == ENOTDIR) {
            if (out_missing) *out_missing = true;
            return OP_SUCCESS;
        }
        return st;
    }

    st = read_file_alloc(pub_path, &enc_pub, &enc_pub_len, &err_pub);
    if (st != OP_SUCCESS) {
        free(enc_priv);
        if (err_pub == ENOENT || err_pub == ENOTDIR) {
            if (out_missing) *out_missing = true;
            return OP_SUCCESS;
        }
        return st;
    }

    uint8_t *priv_buf = NULL;
    size_t priv_len = 0;
    uint8_t *pub_buf = NULL;
    size_t pub_len = 0;

    st = LocalSaveDecrypt(enc_priv, enc_priv_len, password, password_len, &priv_buf, &priv_len);
    if (st != OP_SUCCESS) {
        free(enc_priv);
        free(enc_pub);
        return st;
    }
    st = LocalSaveDecrypt(enc_pub, enc_pub_len, password, password_len, &pub_buf, &pub_len);
    if (st != OP_SUCCESS) {
        free(enc_priv);
        free(enc_pub);
        free(priv_buf);
        return st;
    }

    free(enc_priv);
    free(enc_pub);

    if (priv_len != UINT256_SIZE || pub_len != UINT256_SIZE) {
        free(priv_buf);
        free(pub_buf);
        return OP_INVALID_INPUT;
    }

    st = uint256_deserialize_be(priv_buf, priv_len, out_priv);
    if (st != OP_SUCCESS) {
        free(priv_buf);
        free(pub_buf);
        return st;
    }
    st = uint256_deserialize_be(pub_buf, pub_len, out_pub);
    free(priv_buf);
    free(pub_buf);
    return st;
}

/*
 * Load Ed25519 signing keys. If missing, generate and save them.
 */
UTIL_INLINE OpStatus_t load_sign_keys(const char *network_name,
                                      uint256 *out_priv,
                                      uint256 *out_pub,
                                      const char *password,
                                      size_t password_len)
{
    if (!out_priv || !out_pub) return OP_NULL_PTR;

    bool missing = false;
    OpStatus_t st = load_keys_from_wallet(network_name, PKCERTCHAIN_SIGN_PRIV_FILE, PKCERTCHAIN_SIGN_PUB_FILE,
                                          password, password_len, out_priv, out_pub, &missing);
    if (st != OP_SUCCESS) return st;
    if (!missing) return OP_SUCCESS;

    st = GenerateSignKeys(out_priv, out_pub, network_name);
    if (st != OP_SUCCESS) return st;
    return save_sign_keys(network_name, out_priv, out_pub, password, password_len);
}

/*
 * Load X25519 encryption keys. If missing, generate and save them.
 */
UTIL_INLINE OpStatus_t load_enc_keys(const char *network_name,
                                     uint256 *out_priv,
                                     uint256 *out_pub,
                                     const char *password,
                                     size_t password_len)
{
    if (!out_priv || !out_pub) return OP_NULL_PTR;

    bool missing = false;
    OpStatus_t st = load_keys_from_wallet(network_name, PKCERTCHAIN_ENC_PRIV_FILE, PKCERTCHAIN_ENC_PUB_FILE,
                                          password, password_len, out_priv, out_pub, &missing);
    if (st != OP_SUCCESS) return st;
    if (!missing) return OP_SUCCESS;

    st = GenerateEncKeys(out_priv, out_pub, network_name);
    if (st != OP_SUCCESS) return st;
    return save_enc_keys(network_name, out_priv, out_pub, password, password_len);
}

#endif // LINUXUTILS_H
