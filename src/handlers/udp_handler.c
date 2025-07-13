#include "udp.h"
#include <string.h>
#include <stdio.h>

int parse_udp_header(const unsigned char *frame, size_t frame_len, udp_packet *out) {
    if (!frame || !out)
        return -1;

    if (out->ip.protocol != IPPROTO_UDP) {
        fprintf(stderr, "Error: Not a UDP packet => Protocol %d\n", out->ip.protocol);
        return -1;
    }

    if (frame_len < sizeof(udp_header)) {
        fprintf(stderr, "Error: Frame too short for UDP header\n");
        return -1;
    }

    const udp_header *udp = (const udp_header *)frame;

    out->src_port = ntohs(udp->uh_sport);
    out->dst_port = ntohs(udp->uh_dport);
    out->length   = ntohs(udp->uh_ulen);
    out->checksum = ntohs(udp->uh_sum);

    if (out->length < sizeof(udp_header)) {
        fprintf(stderr, "Error: Invalid UDP length field (%u)\n", out->length);
        return -1;
    }

    out->data_len = out->length - sizeof(udp_header);

    // Optional: Validate UDP length vs IP total length
    uint16_t ip_total_len = out->ip.total_len;
    uint8_t  ip_hdr_len   = out->ip.header_len;
    uint16_t udp_payload_len = ip_total_len - ip_hdr_len;
    if (out->length > udp_payload_len) {
        fprintf(stderr, "Warning: UDP length field (%u) exceeds remaining IP payload (%u)\n",
                out->length, udp_payload_len);
    }

    // Detect common UDP services
    if (out->src_port == 53 || out->dst_port == 53)
        strcpy(out->service_str, "DNS");
    else if (out->src_port == 67 || out->dst_port == 67 || out->src_port == 68 || out->dst_port == 68)
        strcpy(out->service_str, "DHCP");
    else if (out->src_port == 123 || out->dst_port == 123)
        strcpy(out->service_str, "NTP");
    else if (out->src_port == 161 || out->dst_port == 161 || out->src_port == 162 || out->dst_port == 162)
        strcpy(out->service_str, "SNMP");
    else if (out->src_port == 69 || out->dst_port == 69)
        strcpy(out->service_str, "TFTP");
    else if (out->src_port == 520 || out->dst_port == 520)
        strcpy(out->service_str, "RIP");
    else
        strcpy(out->service_str, "Unknown");

    return sizeof(udp_header);
}

void print_udp_packet(const unsigned char *packet, uint32_t wire_len, const udp_packet *p) {
    puts("\n=== UDP Packet (Parsed) ===\n");

    printf("Src MAC          : %s\n", p->ether.src_mac);
    printf("Dst MAC          : %s\n", p->ether.dst_mac);
    printf("Ethertype        : 0x%04x\n", ntohs(p->ether.ethertype));
    puts("");

    printf("Source IP        : %s\n", p->ip.src);
    printf("Destination IP   : %s\n", p->ip.dst);
    puts("");

    printf("Source Port      : %u\n", p->src_port);
    printf("Destination Port : %u\n", p->dst_port);
    printf("Length Field     : %u bytes\n", p->length);
    printf("Data Length      : %u bytes\n", p->data_len);
    printf("Checksum         : 0x%04x\n", p->checksum);
    printf("Service          : %s\n", p->service_str);
    puts("");

    printf("Total on wire    : %u bytes\n", wire_len);
    printf("Raw Bytes        : ");
    dump_hex_single_line(packet, wire_len);

    puts("\n===========================\n");
}

void udp_handler(
    unsigned char *user,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
) {
    (void)user;

    udp_packet pkt;
    int offset = 0;

    offset += parse_ethernet_header(packet + offset, header->len - offset, &pkt.ether);
    offset += parse_ip_header(packet + offset, header->len - offset, &pkt.ip);
    if (parse_udp_header(packet + offset, header->len - offset, &pkt) >= 0) {
        print_udp_packet(packet, header->len, &pkt);
    }
}
