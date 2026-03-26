#ifndef HMAC_ROUTING_H
#define HMAC_ROUTING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define ROUTING_KEY_SIZE 32
#define ROUTING_HMAC_SIZE 32
#define MAX_PATH_HOPS 16

typedef struct {
    uint8_t payload[256];
    size_t payload_len;
    uint8_t path_vector[MAX_PATH_HOPS]; // Array of NodeIDs representing the route
    size_t path_len;
    uint8_t hmac[ROUTING_HMAC_SIZE];
    uint32_t nonce;
} RoutingPacket;

/**
 * @brief Derives a per-hop key: K_i = H(K_{i-1} || NodeID_i)
 */
static inline void derive_key(const uint8_t *k_prev, uint8_t node_id, uint8_t *k_out) {
    uint8_t buf[ROUTING_KEY_SIZE + 1];
    memcpy(buf, k_prev, ROUTING_KEY_SIZE);
    buf[ROUTING_KEY_SIZE] = node_id;
    
    unsigned int len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, buf, sizeof(buf));
    EVP_DigestFinal_ex(mdctx, k_out, &len);
    EVP_MD_CTX_free(mdctx);
}

/**
 * @brief Computes HMAC over the payload, path vector, and nonce.
 */
static inline void compute_hmac(const uint8_t *key, const RoutingPacket *pkt, uint8_t *hmac_out) {
    unsigned int len = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, ROUTING_KEY_SIZE, EVP_sha256(), NULL);
    HMAC_Update(ctx, pkt->payload, pkt->payload_len);
    HMAC_Update(ctx, pkt->path_vector, pkt->path_len);
    HMAC_Update(ctx, (const uint8_t*)&pkt->nonce, sizeof(pkt->nonce));
    HMAC_Final(ctx, hmac_out, &len);
    HMAC_CTX_free(ctx);
}

/**
 * @brief 1. Source creates initial packet
 */
static inline void create_packet(RoutingPacket *pkt, const uint8_t *payload, size_t payload_len, const uint8_t *k0, uint32_t nonce) {
    memset(pkt, 0, sizeof(RoutingPacket));
    memcpy(pkt->payload, payload, payload_len);
    pkt->payload_len = payload_len;
    pkt->nonce = nonce;
    pkt->path_len = 0;
    
    // Initial HMAC using K0
    compute_hmac(k0, pkt, pkt->hmac);
}

/**
 * @brief 2. Per-hop HMAC update and verification
 * Modifies the packet in-place by appending NodeID and overwriting HMAC.
 */
static inline bool forward_packet(RoutingPacket *pkt, uint8_t node_id_i, const uint8_t *k_prev, uint8_t *k_out_derived) {
    // A. Verify previous HMAC
    uint8_t expected_hmac[ROUTING_HMAC_SIZE];
    compute_hmac(k_prev, pkt, expected_hmac);
    if (memcmp(expected_hmac, pkt->hmac, ROUTING_HMAC_SIZE) != 0) {
        return false; // Verification failed (Tampering detected!)
    }

    // B. Append node to path vector
    if (pkt->path_len >= MAX_PATH_HOPS) {
        return false; // Route too long
    }
    pkt->path_vector[pkt->path_len++] = node_id_i;

    // C. Derive new key: Ki = H(K_{i-1} || NodeID_i)
    derive_key(k_prev, node_id_i, k_out_derived);

    // D. Compute new HMAC and overwrite in-place
    compute_hmac(k_out_derived, pkt, pkt->hmac);
    
    return true;
}

/**
 * @brief 3. Destination verifies full payload and route integrity
 */
static inline bool verify_packet(const RoutingPacket *pkt, const uint8_t *k0) {
    uint8_t current_key[ROUTING_KEY_SIZE];
    memcpy(current_key, k0, ROUTING_KEY_SIZE);

    // Iteratively compute K_i = H(K_{i-1} || NodeID_i) across the entire path
    for (size_t i = 0; i < pkt->path_len; i++) {
        uint8_t next_key[ROUTING_KEY_SIZE];
        derive_key(current_key, pkt->path_vector[i], next_key);
        memcpy(current_key, next_key, ROUTING_KEY_SIZE);
    }

    // `current_key` is now exactly the final per-hop key `Kn`
    // Recompute the HMAC and verify against the packet's in-place HMAC
    uint8_t expected_hmac[ROUTING_HMAC_SIZE];
    compute_hmac(current_key, pkt, expected_hmac);

    return memcmp(expected_hmac, pkt->hmac, ROUTING_HMAC_SIZE) == 0;
}

#endif // HMAC_ROUTING_H
