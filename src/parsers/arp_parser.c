#include "arp.h"
#include "ethernet.h"

int parse_arp_packet(const unsigned char *frame, size_t frame_len, arp_packet *out) {
    // 1. Sanity check
    if (!frame || !out)
        return -1;
    // Must contain Ethernet + ARP header
    if (frame_len < sizeof(arp_header)) {
        fprintf(stderr, "Frame too short: %zu bytes\n", frame_len);
        return -1;
    }
    // Confirm ARP ethertype
    if (out->ether.ethertype != ETHERTYPE_ARP) {
        fprintf(stderr, "Not an ARP frame: 0x%04x\n", ntohs(out->ether.ethertype));
        return -1;
    }

    // 2. parse ARP header
    const arp_header *arp = (const arp_header *)frame;

    // Validate ARP header sizes
    if (arp->hln != 6 || arp->pln != 4) {
        fprintf(stderr, "Unsupported ARP sizes: hw_len=%u, proto_len=%u\n", arp->hln, arp->pln);
        return -1;
    }

    // Parse ARP fields
    out->hardware_type = ntohs(arp->hrd);
    out->protocol_type = ntohs(arp->pro);
    out->hardware_size = arp->hln;
    out->protocol_size = arp->pln;
    out->operation     = ntohs(arp->op);

    mac_to_str(arp->sha, out->sender_mac, sizeof(out->sender_mac)),
    mac_to_str(arp->tha, out->target_mac, sizeof(out->target_mac)),
    inet_ntop(AF_INET, arp->sip, out->sender_ip, sizeof(out->sender_ip));
    inet_ntop(AF_INET, arp->tip, out->target_ip, sizeof(out->target_ip));

    return sizeof(arp_header); // Return number of bytes parsed after Ethernet
}