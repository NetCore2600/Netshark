#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int parse_qname(const unsigned char *data, size_t len, size_t *offset, char *out) {
    size_t i = *offset;
    size_t out_i = 0;

    while (i < len && data[i] != 0) {
        uint8_t label_len = data[i++];
        if (label_len == 0 || label_len + i > len || out_i + label_len + 1 >= DNS_MAX_NAME_LEN)
            return -1;

        memcpy(&out[out_i], &data[i], label_len);
        out_i += label_len;
        i += label_len;
        out[out_i++] = '.';
    }

    if (i >= len || out_i == 0)
        return -1;

    out[out_i - 1] = '\0'; // replace last dot
    *offset = i + 1;
    return 0;
}

int parse_dns_packet(const unsigned char *data, size_t len, dns_packet *out) {
    if (!data || len < 12 || !out) return -1;

    out->id = ntohs(*(uint16_t *)(data));
    out->flags = ntohs(*(uint16_t *)(data + 2));
    out->qdcount = ntohs(*(uint16_t *)(data + 4));
    out->ancount = ntohs(*(uint16_t *)(data + 6));
    out->nscount = ntohs(*(uint16_t *)(data + 8));
    out->arcount = ntohs(*(uint16_t *)(data + 10));

    size_t offset = 12;
    if (out->qdcount > 0 && parse_qname(data, len, &offset, out->qname) == 0) {
        if (offset + 4 > len) return -1;
        out->qtype = ntohs(*(uint16_t *)(data + offset));
        out->qclass = ntohs(*(uint16_t *)(data + offset + 2));
    }

    out->total_len = len;
    return 0;
}

void print_dns_packet(const unsigned char *packet, uint32_t wire_len, const dns_packet *dns) {
    printf("=== DNS Packet ===\n");
    printf("Src MAC        : %s\n", dns->udp.ether.src_mac);
    printf("Dst MAC        : %s\n", dns->udp.ether.dst_mac);
    printf("Ethertype      : 0x%04x\n\n", dns->udp.ether.ethertype);

    printf("Source IP      : %s\n", dns->udp.ip.src);
    printf("Destination IP : %s\n\n", dns->udp.ip.dst);

    printf("Source Port    : %u\n", dns->udp.src_port);
    printf("Dest Port      : %u\n\n", dns->udp.dst_port);

    printf("Transaction ID : 0x%04x\n", dns->id);
    printf("Flags          : 0x%04x\n", dns->flags);
    printf("Questions      : %u\n", dns->qdcount);
    printf("Answers        : %u\n", dns->ancount);
    printf("Authority RRs  : %u\n", dns->nscount);
    printf("Additional RRs : %u\n", dns->arcount);
    if (dns->qdcount > 0) {
        printf("Query Name     : %s\n", dns->qname);
        printf("Query Type     : %u\n", dns->qtype);
        printf("Query Class    : %u\n", dns->qclass);
    }

    printf("\nRaw Bytes      : ");
    dump_hex_single_line(packet, wire_len);
    printf("\n===========================\n");
}

void dns_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;

    dns_packet dns;
    int offset = 0;

    offset += parse_ethernet_header(packet, header->len, &dns.udp.ether);
    offset += parse_ip_header(packet + offset, header->len - offset, &dns.udp.ip);
    offset += parse_udp_header(packet + offset, header->len - offset, &dns.udp);

    uint16_t sport = dns.udp.src_port;
    uint16_t dport = dns.udp.dst_port;

    if (sport != 53 && dport != 53) {
        fprintf(stderr, "Not a DNS packet\n");
        return;
    }

    const unsigned char *payload = packet + offset;
    int payload_len = dns.udp.data_len;

    if (parse_dns_packet(payload, payload_len, &dns) == 0) {
        print_dns_packet(packet, header->len, &dns);
    } else {
        fprintf(stderr, "Failed to parse DNS packet.\n");
    }
}
