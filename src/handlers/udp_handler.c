#include "udp.h"
#include <string.h>
#include <stdio.h>

int parse_udp_packet(const unsigned char *frame, size_t frame_len, udp_packet *out) {
    if (!frame || !out) return -1;

    memset(out, 0, sizeof(*out));

    // 1. Parse Ethernet
    int eth_offset = parse_ethernet_frame(frame, frame_len, &out->ether);
    if (eth_offset < 0 || frame_len < eth_offset + sizeof(ip_header))
        return -1;
    frame += eth_offset;
    frame_len -= eth_offset;
    
    // 2. Parse IP header using helper
    int ip_offset = parse_ip_header(frame, frame_len, &out->ip);
    if (ip_offset < 0)
        return -1;
    frame += ip_offset;
    frame_len -= ip_offset;

    // 3. Sanity check
    if (out->ip.protocol != IPPROTO_UDP)
        return -1;
    if (frame_len < sizeof(udp_header))
        return -1;

    // 4. Parse UDP header
    const udp_header *udp = (const udp_header *)(frame);
    out->src_port = ntohs(udp->uh_sport);
    out->dst_port = ntohs(udp->uh_dport);
    out->length   = ntohs(udp->uh_ulen);
    out->checksum = ntohs(udp->uh_sum);
    out->data_len = out->length - sizeof(udp_header);

    // 6. Detect UDP-based service
    if (out->src_port == 53 || out->dst_port == 53)
        strcpy(out->service_str, "DNS");
    else if (out->src_port == 67 || out->dst_port == 67 || out->src_port == 68 || out->dst_port == 68)
        strcpy(out->service_str, "DHCP");
    else if (out->src_port == 123 || out->dst_port == 123)
        strcpy(out->service_str, "NTP");
    else if (out->src_port == 161 || out->dst_port == 161 || out->src_port == 162 || out->dst_port == 162)
        strcpy(out->service_str, "SNMP");
    else
        strcpy(out->service_str, "Unknown");

    return 0;
}


void print_udp_packet(const unsigned char *packet, uint32_t wire_len, const udp_packet *p) {
    puts("\n=== UDP Packet (Parsed) ===");

    printf("Src MAC        : %s\n", p->ether.src_mac);
    printf("Dst MAC        : %s\n", p->ether.dst_mac);
    printf("Ethertype      : 0x%04x\n", ntohs(p->ether.ethertype));
    puts("\n");
    printf("Source IP      : %s\n", p->ip.src);
    printf("Destination IP : %s\n", p->ip.dst);
    puts("\n");
    printf("Source Port    : %u\n", p->src_port);
    printf("Destination Port: %u\n", p->dst_port);
    printf("Length Field   : %u bytes\n", p->length);
    printf("Data Length    : %u bytes\n", p->data_len);
    printf("Checksum       : 0x%04x\n", p->checksum);
    printf("Service        : %s\n", p->service_str);
    puts("\n");
    printf("Total on wire  : %u bytes\n", wire_len);
    printf("Raw Bytes      : "); dump_hex_single_line(packet, wire_len);

    puts("===========================");
}

void udp_handler(
    unsigned char *user,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
) {
    (void)user;

    udp_packet pkt;
    if (parse_udp_packet(packet, header->len, &pkt) == 0)
        print_udp_packet(packet, header->len, &pkt);
}
