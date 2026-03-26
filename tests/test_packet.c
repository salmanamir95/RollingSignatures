#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "packet.h"

// Helper to generate a raw test keypair using OpenSSL
static void generate_test_keys(uint256 *priv, uint256 *pub) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(pctx, &pkey);
    
    uint8_t priv_bytes[32], pub_bytes[32];
    size_t priv_len = 32, pub_len = 32;
    EVP_PKEY_get_raw_private_key(pkey, priv_bytes, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_bytes, &pub_len);
    
    // The SignUtils functions serialize keys to Big-Endian before passing to OpenSSL.
    // So we must deserialize the raw OpenSSL bytes into uint256 using Big-Endian
    // to ensure they match once serialized again.
    uint256_deserialize_be(priv_bytes, 32, priv);
    uint256_deserialize_be(pub_bytes, 32, pub);
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

int main() {
    uint256 priv, pub;
    generate_test_keys(&priv, &pub);

    const char *payload = "Hello Rolling Signatures!";
    size_t payload_len = strlen(payload);

    uint512 sig;
    OpStatus_t st = packet_sign((const uint8_t*)payload, payload_len, &priv, &sig);
    if (st != OP_SUCCESS) {
        printf("Failed to sign!\n");
        return 1;
    }

    // Verify valid signature
    OpStatus_t v_st = packet_verify((const uint8_t*)payload, payload_len, &sig, &pub);
    if (v_st != OP_SIGN_VERIFIED_TRUE) {
        printf("Failed to verify valid signature! Expected %d but got %d\n", OP_SIGN_VERIFIED_TRUE, v_st);
        return 1;
    }
    printf("1. Valid signature verified successfully!\n");

    // Verify invalid signature
    uint512 bad_sig = sig;
    bad_sig.w[0] ^= 0xFFFFFFFFFFFFFFFF; // flip bytes
    v_st = packet_verify((const uint8_t*)payload, payload_len, &bad_sig, &pub);
    if (v_st == OP_SIGN_VERIFIED_TRUE) {
        printf("Invalid signature incorrectly verified!\n");
        return 1;
    }
    printf("2. Invalid signature rejected correctly (returned %d)!\n", v_st);

    // Test Serialization
    uint8_t buffer[1024];
    packet_serialize((const uint8_t*)payload, payload_len, &sig, buffer, sizeof(buffer));

    uint8_t out_payload[1024];
    uint512 out_sig;
    packet_deserialize(buffer, payload_len + UINT512_SIZE, payload_len, out_payload, &out_sig);

    if (memcmp(payload, out_payload, payload_len) == 0 && memcmp(&sig, &out_sig, sizeof(uint512)) == 0) {
        printf("3. Serialization and deserialization successful!\n");
    } else {
        printf("Serialization mismatch!\n");
        return 1;
    }

    return 0;
}
