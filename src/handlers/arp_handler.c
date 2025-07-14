#include "arp.h"

void print_arp_packet(const unsigned char *packet, uint32_t wire_len, const arp_packet *p) {
    puts("\n=== ARP Packet ===");

    printf("Src MAC          : %s\n", p->ether.src_mac);
    printf("Dst MAC          : %s\n", p->ether.dst_mac);
    printf("EtherType        : 0x%04x\n", ntohs(p->ether.ethertype));
    puts("");

    printf("Hardware Type    : %s (%u)\n",
           p->hardware_type == ARP_HARDWARE_TYPE_ETHERNET ? "Ethernet" : "Other",
           p->hardware_type);
    printf("Protocol Type    : 0x%04x\n", p->protocol_type);
    printf("HW Addr Length   : %u bytes\n", p->hardware_size);
    printf("Proto Addr Length: %u bytes\n", p->protocol_size);
    printf("Operation        : %s (%u)\n",
           p->operation == ARP_REQUEST ? "Request" :
           p->operation == ARP_REPLY   ? "Reply"   : "Unknown",
           p->operation);
    printf("Sender MAC       : %s\n", p->sender_mac);
    printf("Sender IP        : %s\n", p->sender_ip);
    printf("Target MAC       : %s\n", p->target_mac);
    printf("Target IP        : %s\n", p->target_ip);
    puts("");

    printf("Total on wire    : %u bytes\n", wire_len);
    printf("Raw Bytes        : ");
    dump_hex_single_line(packet, wire_len);

    puts("\n===========================\n");
}

void arp_handler(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *frame) {
    (void)user;
    arp_packet pkt;
    uint32_t framelen = hdr->len;

    int offset = parse_ethernet_header(frame, framelen, &pkt.ether);

    if (parse_arp_packet(frame + offset, framelen - offset, &pkt) >= 0)
        print_arp_packet(frame, framelen, &pkt);
    // silently ignore otherwise
}
