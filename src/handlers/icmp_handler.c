#include "icmp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

const char* icmp_type_to_str(uint8_t type) {
    switch (type) {
        case 0:  return "Echo Reply";
        case 3:  return "Destination Unreachable";
        case 4:  return "Source Quench (Deprecated)";
        case 5:  return "Redirect";
        case 8:  return "Echo Request";
        case 9:  return "Router Advertisement";
        case 10: return "Router Solicitation";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp";
        case 14: return "Timestamp Reply";
        default: return "Unknown";
    }
}

const char *icmp_code_to_str(uint8_t type, uint8_t code) {
    switch (type) {
        case 0:
            return "";
        case 3: // Destination Unreachable
            switch (code) {
                case 0: return "Network Unreachable";
                case 1: return "Host Unreachable";
                case 2: return "Protocol Unreachable";
                case 3: return "Port Unreachable";
                case 4: return "Fragmentation Needed";
                case 5: return "Source Route Failed";
                case 6: return "Network Unknown";
                case 7: return "Host Unknown";
                case 9: return "Network Admin Prohibited";
                case 10: return "Host Admin Prohibited";
                case 13: return "Communication Admin Prohibited";
                default: return "Unknown Code (Destination Unreachable)";
            }
        case 5: // Redirect
            switch (code) {
                case 0: return "Redirect for Network";
                case 1: return "Redirect for Host";
                case 2: return "Redirect for TOS and Network";
                case 3: return "Redirect for TOS and Host";
                default: return "Unknown Code (Redirect)";
            }
        case 8:
            return "";
        case 11: // Time Exceeded
            return code == 0 ? "TTL Exceeded in Transit" :
                   code == 1 ? "Fragment Reassembly Time Exceeded" :
                               "Unknown Code (Time Exceeded)";
        case 12: // Parameter Problem
            return code == 0 ? "Pointer Indicates Error" :
                   code == 1 ? "Missing Required Option" :
                   code == 2 ? "Bad Length" :
                               "Unknown Code (Parameter Problem)";
        default:
            return "Code not applicable for this type";
    }
}


int parse_icmp_packet(const unsigned char *data, size_t len, icmp_packet *out) {
    if (!data || len < 8 || !out) return -1;

    out->type = data[0];
    out->code = data[1];
    out->checksum = (data[2] << 8) + data[3];
    out->identifier = (data[4] << 8) + data[5];
    out->sequence = (data[6] << 8) + data[7];

    out->payload_len = len - 8;
    if (out->payload_len > sizeof(out->payload))
        out->payload_len = sizeof(out->payload);

    memcpy(out->payload, data + 8, out->payload_len);

    return 0;
}

void print_icmp_packet(const unsigned char *packet, uint32_t wire_len, const icmp_packet *icmp) {
    printf("\n=== ICMP Packet ===\n");
    printf("Src MAC        : %s\n", icmp->ether.src_mac);
    printf("Dst MAC        : %s\n", icmp->ether.dst_mac);
    printf("Ethertype      : 0x%04x\n", icmp->ether.ethertype);
    puts("\n");

    printf("Source IP      : %s\n", icmp->ip.src);
    printf("Destination IP : %s\n", icmp->ip.dst);
    puts("\n");

    printf("ICMP Type      : %u (%s)\n", icmp->type, icmp_type_to_str(icmp->type));
    printf("ICMP Code      : %u (%s)\n", icmp->code, icmp_code_to_str(icmp->type, icmp->code));
    printf("Checksum       : 0x%04x\n", icmp->checksum);
    printf("Identifier     : %u\n", icmp->identifier);
    printf("Sequence       : %u\n", icmp->sequence);
    printf("Payload Length : %u bytes\n", icmp->payload_len);

    printf("Raw Bytes      : ");
    dump_hex_single_line(packet, wire_len);
    printf("\n===========================\n");
}

void icmp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;

    icmp_packet icmp;
    int offset = 0;

    offset += parse_ethernet_header(packet, header->len, &icmp.ether);
    offset += parse_ip_header(packet + offset, header->len - offset, &icmp.ip);

    // Ensure it's actually ICMP
    if (icmp.ip.protocol != IPPROTO_ICMP) {
        fprintf(stderr, "Not an ICMP packet (protocol = %d)\n", icmp.ip.protocol);
        return;
    }

    const unsigned char *icmp_payload = packet + offset;
    int icmp_len = header->len - offset;

    if (parse_icmp_packet(icmp_payload, icmp_len, &icmp) == 0) {
        print_icmp_packet(packet, header->len, &icmp);
    } else {
        fprintf(stderr, "Failed to parse ICMP packet.\n");
    }
}
