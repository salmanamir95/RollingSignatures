#ifndef ENCUTILS_H
#define ENCUTILS_H

#include "pkcertchain_config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "datatype/uint256_t.h"
#include "datatype/OpStatus.h"
#include "util/Size_Offsets.h"
#include "util/WalletSetup.h"

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

#define PKCERTCHAIN_ENC_MAGIC "PKC1"
#define PKCERTCHAIN_ENC_MAGIC_LEN 4
#define PKCERTCHAIN_ENC_SALT_LEN 16
#define PKCERTCHAIN_ENC_IV_LEN   12
#define PKCERTCHAIN_ENC_TAG_LEN  16
#define PKCERTCHAIN_ENC_KEY_LEN  32

/*
 * Generate X25519 encryption keypair.
 *
 * Output:
 *   - out_priv: 32-byte private key
 *   - out_pub: 32-byte public key
 */
UTIL_INLINE OpStatus_t GenerateEncKeys(uint256 *out_priv, uint256 *out_pub, const char *network_name)
{
    if (!out_priv || !out_pub) return OP_NULL_PTR;
    if (need_pkcertchain_setup(network_name)) {
        OpStatus_t st = create_wallet(network_name);
        if (st != OP_SUCCESS) return st;
    }
    uint256_zero(out_priv);
    uint256_zero(out_pub);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return OP_INVALID_INPUT;
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return OP_INVALID_INPUT;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return OP_INVALID_INPUT;
    }

    size_t priv_len = UINT256_SIZE;
    size_t pub_len = UINT256_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey, (unsigned char *)out_priv->w, &priv_len) != 1 ||
        EVP_PKEY_get_raw_public_key(pkey, (unsigned char *)out_pub->w, &pub_len) != 1 ||
        priv_len != UINT256_SIZE || pub_len != UINT256_SIZE) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        uint256_zero(out_priv);
        uint256_zero(out_pub);
        return OP_INVALID_INPUT;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return OP_SUCCESS;
}

/*
 * Encrypt a buffer using AES-256-GCM with a password-derived key.
 *
 * Output format:
 *   [magic(4)][salt(16)][iv(12)][tag(16)][ciphertext(N)]
 *
 * Returns:
 *   - OP_SUCCESS on success
 *   - OP_INVALID_INPUT on failure
 */
UTIL_INLINE OpStatus_t LocalSaveEncrypt(const uint8_t *in,
                                        size_t in_len,
                                        const char *password,
                                        size_t password_len,
                                        uint8_t **out,
                                        size_t *out_len)
{
    if (!in || in_len == 0 || !password || password_len == 0 || !out || !out_len) return OP_INVALID_INPUT;

    uint8_t salt[PKCERTCHAIN_ENC_SALT_LEN];
    uint8_t iv[PKCERTCHAIN_ENC_IV_LEN];
    uint8_t key[PKCERTCHAIN_ENC_KEY_LEN];
    if (RAND_bytes(salt, sizeof(salt)) != 1) return OP_INVALID_INPUT;
    if (RAND_bytes(iv, sizeof(iv)) != 1) return OP_INVALID_INPUT;

    // Derive key = SHA256(password || salt)
    SHA256_CTX sha_ctx;
    if (SHA256_Init(&sha_ctx) != 1 ||
        SHA256_Update(&sha_ctx, (const unsigned char *)password, password_len) != 1 ||
        SHA256_Update(&sha_ctx, salt, sizeof(salt)) != 1 ||
        SHA256_Final(key, &sha_ctx) != 1) {
        return OP_INVALID_INPUT;
    }

    const size_t header_len = PKCERTCHAIN_ENC_MAGIC_LEN + PKCERTCHAIN_ENC_SALT_LEN +
                              PKCERTCHAIN_ENC_IV_LEN + PKCERTCHAIN_ENC_TAG_LEN;
    const size_t total_len = header_len + in_len;

    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return OP_INVALID_INPUT;

    memcpy(buf, PKCERTCHAIN_ENC_MAGIC, PKCERTCHAIN_ENC_MAGIC_LEN);
    memcpy(buf + PKCERTCHAIN_ENC_MAGIC_LEN, salt, sizeof(salt));
    memcpy(buf + PKCERTCHAIN_ENC_MAGIC_LEN + sizeof(salt), iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(buf);
        return OP_INVALID_INPUT;
    }

    int len = 0;
    int ciphertext_len = 0;
    uint8_t *ciphertext = buf + header_len;
    uint8_t *tag = buf + PKCERTCHAIN_ENC_MAGIC_LEN + PKCERTCHAIN_ENC_SALT_LEN + PKCERTCHAIN_ENC_IV_LEN;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PKCERTCHAIN_ENC_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len, in, (int)in_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return OP_INVALID_INPUT;
    }

    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return OP_INVALID_INPUT;
    }
    ciphertext_len += len;

    if ((size_t)ciphertext_len != in_len) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return OP_INVALID_INPUT;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, PKCERTCHAIN_ENC_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return OP_INVALID_INPUT;
    }

    EVP_CIPHER_CTX_free(ctx);
    *out = buf;
    *out_len = total_len;
    return OP_SUCCESS;
}

/*
 * Decrypt a buffer produced by LocalSaveEncrypt.
 *
 * Returns:
 *   - OP_SUCCESS on success
 *   - OP_INVALID_INPUT on failure
 */
UTIL_INLINE OpStatus_t LocalSaveDecrypt(const uint8_t *in,
                                        size_t in_len,
                                        const char *password,
                                        size_t password_len,
                                        uint8_t **out,
                                        size_t *out_len)
{
    if (!in || in_len == 0 || !password || password_len == 0 || !out || !out_len) return OP_INVALID_INPUT;

    const size_t header_len = PKCERTCHAIN_ENC_MAGIC_LEN + PKCERTCHAIN_ENC_SALT_LEN +
                              PKCERTCHAIN_ENC_IV_LEN + PKCERTCHAIN_ENC_TAG_LEN;
    if (in_len < header_len) return OP_INVALID_INPUT;

    if (memcmp(in, PKCERTCHAIN_ENC_MAGIC, PKCERTCHAIN_ENC_MAGIC_LEN) != 0) return OP_INVALID_INPUT;

    const uint8_t *salt = in + PKCERTCHAIN_ENC_MAGIC_LEN;
    const uint8_t *iv = salt + PKCERTCHAIN_ENC_SALT_LEN;
    const uint8_t *tag = iv + PKCERTCHAIN_ENC_IV_LEN;
    const uint8_t *ciphertext = in + header_len;
    const size_t ciphertext_len = in_len - header_len;

    uint8_t key[PKCERTCHAIN_ENC_KEY_LEN];
    // Derive key = SHA256(password || salt)
    SHA256_CTX sha_ctx;
    if (SHA256_Init(&sha_ctx) != 1 ||
        SHA256_Update(&sha_ctx, (const unsigned char *)password, password_len) != 1 ||
        SHA256_Update(&sha_ctx, salt, PKCERTCHAIN_ENC_SALT_LEN) != 1 ||
        SHA256_Final(key, &sha_ctx) != 1) {
        return OP_INVALID_INPUT;
    }

    uint8_t *plaintext = (uint8_t *)malloc(ciphertext_len);
    if (!plaintext) return OP_INVALID_INPUT;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(plaintext);
        return OP_INVALID_INPUT;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PKCERTCHAIN_ENC_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return OP_INVALID_INPUT;
    }

    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, PKCERTCHAIN_ENC_TAG_LEN, (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return OP_INVALID_INPUT;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *out = plaintext;
    *out_len = (size_t)plaintext_len;
    return OP_SUCCESS;
}

#endif // ENCUTILS_H
