#include <stdio.h>
#include <string.h>
#include "hmac_routing.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    uint8_t K0[ROUTING_KEY_SIZE];
    memset(K0, 0xAB, ROUTING_KEY_SIZE); // Dummy Master Secret `K0`
    
    const char* message = "Secure Multihop Routing Payload with HMAC!";
    
    RoutingPacket packet;
    create_packet(&packet, (const uint8_t*)message, strlen(message), K0, 9999);
    
    printf("--- INITIAL PACKET (SOURCE) ---\n");
    print_hex("HMAC_0", packet.hmac, ROUTING_HMAC_SIZE);
    
    // 5-Node Example Path
    uint8_t path_nodes[] = {11, 22, 33, 44, 55};
    size_t num_hops = sizeof(path_nodes) / sizeof(path_nodes[0]);
    
    uint8_t current_key[ROUTING_KEY_SIZE];
    memcpy(current_key, K0, ROUTING_KEY_SIZE);
    
    for (size_t i = 0; i < num_hops; i++) {
        uint8_t node_id = path_nodes[i];
        uint8_t next_key[ROUTING_KEY_SIZE];
        
        printf("\n--- HOP %zu (Node %d) ---\n", i + 1, node_id);
        
        // Node processes the packet
        bool ok = forward_packet(&packet, node_id, current_key, next_key);
        if (!ok) {
            printf("CRITICAL: Verification FAILED at Hop %zu (Node %d)!\n", i + 1, node_id);
            return 1;
        }
        
        printf("Incoming HMAC verified! Appending Node %d, deriving new key...\n", node_id);
        memcpy(current_key, next_key, ROUTING_KEY_SIZE); // Hand over derived key for simulation
        
        print_hex("New In-Place HMAC", packet.hmac, ROUTING_HMAC_SIZE);
        
        printf("Path Vector: [");
        for (size_t j = 0; j < packet.path_len; j++) printf("%d%s", packet.path_vector[j], j == packet.path_len-1 ? "" : ", ");
        printf("]\n");
    }
    
    // DESTINATION VERIFICATION
    printf("\n--- DESTINATION VERIFICATION ---\n");
    bool dest_ok = verify_packet(&packet, K0);
    if (!dest_ok) {
        printf("CRITICAL: Destination Verification FAILED!\n");
        return 1;
    }
    printf("Destination Verification OK! Payload and complete 5-Node Path are deeply authenticated.\n");
    
    // TAMPER TEST
    printf("\n--- TAMPER TEST (Path Tampering) ---\n");
    packet.path_vector[2] = 99; // Attacker blindly modifies the routing path
    bool tamper_ok = verify_packet(&packet, K0);
    if (tamper_ok) {
        printf("Tamper Test FAILED! (Accepted tampered packet)\n");
        return 1;
    }
    printf("Tampered packet correctly rejected! The HMAC mismatch caught the modified hop.\n");

    return 0;
}
