#include "arp.h"       
#include "ethernet.h"  
#include "netshark.h" 

int parse_arp_packet(
    const unsigned char *frame,
    size_t              frame_len,
    arp_packet          *out
) {
    if (!frame || !out)
        return -1;

    memset(out, 0, sizeof(*out));  // << Moved here to avoid wiping parsed ether
    if (frame_len < sizeof(ether_header) + sizeof(arp_header)) {
        printf("Frame too short: %zu bytes\n", frame_len);
        return -1;
    }
    
    int offset = parse_ethernet_frame(frame, frame_len, &out->ether);
    if (offset < 0) {
        fprintf(stderr, "Failed to parse Ethernet frame\n");
        return -1;
    }
    
    if (out->ether.ethertype != ETHERTYPE_ARP) {
        printf("Not an ARP frame: 0x%04x\n", ntohs(out->ether.ethertype));
        return -1;
    }

    frame += offset;
    
    const arp_header *arp = (const arp_header *)frame;
    
    if (arp->ar_hln != 6 || arp->ar_pln != 4)
    {
        printf("Unsupported ARP sizes: hw_len=%u, proto_len=%u\n", arp->ar_hln, arp->ar_pln);
        return -1;
    }

    out->hardware_type = ntohs(arp->ar_hrd);
    out->protocol_type = ntohs(arp->ar_pro);
    out->hardware_size = arp->ar_hln;
    out->protocol_size = arp->ar_pln;
    out->operation     = ntohs(arp->ar_op);

    snprintf(out->sender_mac, sizeof(out->sender_mac),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2],
             arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);

    snprintf(out->target_mac, sizeof(out->target_mac),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->ar_tha[0], arp->ar_tha[1], arp->ar_tha[2],
             arp->ar_tha[3], arp->ar_tha[4], arp->ar_tha[5]);

    inet_ntop(AF_INET, arp->ar_sip, out->sender_ip, sizeof(out->sender_ip));
    inet_ntop(AF_INET, arp->ar_tip, out->target_ip, sizeof(out->target_ip));

    return 0; // Success
}



static void print_arp_packet(
    const unsigned char *packet, 
    uint32_t wire_len, 
    const arp_packet *p
) {
    puts("\n=== ARP Packet (Wire Order) ===");

    printf("Dst MAC        : %s\n", p->ether.dst_mac);
    printf("Src MAC        : %s\n", p->ether.src_mac);
    printf("EtherType      : 0x%04x\n", p->ether.ethertype);

    printf("HW Type        : %s (%u)\n",
           p->hardware_type == 1 ? "Ethernet" : "Unknown",
           p->hardware_type);

    printf("Protocol Type  : 0x%04x\n", p->protocol_type);
    printf("HW Addr Length : %u\n", p->hardware_size);
    printf("Proto Addr Len : %u\n", p->protocol_size);

    printf("Operation      : %s (%u)\n",
           p->operation == 1 ? "Request" :
           p->operation == 2 ? "Reply"   : "Other",
           p->operation);

    printf("Sender MAC     : %s\n", p->sender_mac);
    printf("Sender IP      : %s\n", p->sender_ip);
    printf("Target MAC     : %s\n", p->target_mac);
    printf("Target IP      : %s\n", p->target_ip);

    printf("Total on wire  : %u bytes\n", wire_len);
    printf("Raw Bytes      : "); dump_hex_single_line(packet, wire_len); printf("\n");

    puts("===============================");
}


/* ---------- pcap callback ------------------------------------------------- */

void arp_handler(
    unsigned char            *user,
    const struct pcap_pkthdr *hdr,
    const unsigned char      *packet
) {
    (void)user;   // unused

    arp_packet pkt;
    if (parse_arp_packet(packet, hdr->len, &pkt) == 0)
        print_arp_packet(packet, hdr->len, &pkt);

    /* else silently ignore non‑ARP or malformed frames */
}