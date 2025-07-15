#include "mdns.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int parse_mdns_qname(const unsigned char *data, size_t len, size_t *offset, char *out) {
    size_t i = *offset;
    size_t out_i = 0;
    while (i < len && data[i] != 0) {
        uint8_t label_len = data[i++];
        if (label_len == 0 || label_len + i > len || out_i + label_len + 1 >= MDNS_MAX_NAME_LEN)
            return -1;
        memcpy(&out[out_i], &data[i], label_len);
        out_i += label_len;
        i += label_len;
        out[out_i++] = '.';
    }
    if (i >= len || out_i == 0)
        return -1;
    out[out_i - 1] = '\0';
    *offset = i + 1;
    return 0;
}

int parse_mdns_packet(const unsigned char *data, size_t len, mdns_packet *out) {
    if (!data || len < 12 || !out) return -1;
    out->id = ntohs(*(uint16_t *)(data));
    out->flags = ntohs(*(uint16_t *)(data + 2));
    out->qdcount = ntohs(*(uint16_t *)(data + 4));
    out->ancount = ntohs(*(uint16_t *)(data + 6));
    out->nscount = ntohs(*(uint16_t *)(data + 8));
    out->arcount = ntohs(*(uint16_t *)(data + 10));
    size_t offset = 12;
    if (out->qdcount > 0 && parse_mdns_qname(data, len, &offset, out->qname) == 0) {
        if (offset + 4 > len) return -1;
        out->qtype = ntohs(*(uint16_t *)(data + offset));
        out->qclass = ntohs(*(uint16_t *)(data + offset + 2));
    }
    out->total_len = len;
    return 0;
}

void print_mdns_packet(const unsigned char *packet, uint32_t wire_len, const mdns_packet *mdns) {
    printf("=== mDNS Packet ===\n");
    printf("Src MAC        : %s\n", mdns->udp.ether.src_mac);
    printf("Dst MAC        : %s\n", mdns->udp.ether.dst_mac);
    printf("Ethertype      : 0x%04x\n\n", mdns->udp.ether.ethertype);
    printf("Source IP      : %s\n", mdns->udp.ip.src);
    printf("Destination IP : %s\n\n", mdns->udp.ip.dst);
    printf("Source Port    : %u\n", mdns->udp.src_port);
    printf("Dest Port      : %u\n\n", mdns->udp.dst_port);
    printf("Transaction ID : 0x%04x\n", mdns->id);
    printf("Flags          : 0x%04x\n", mdns->flags);
    printf("Questions      : %u\n", mdns->qdcount);
    printf("Answers        : %u\n", mdns->ancount);
    printf("Authority RRs  : %u\n", mdns->nscount);
    printf("Additional RRs : %u\n", mdns->arcount);
    if (mdns->qdcount > 0) {
        printf("Query Name     : %s\n", mdns->qname);
        printf("Query Type     : %u\n", mdns->qtype);
        printf("Query Class    : %u\n", mdns->qclass);
    }
    printf("\nRaw Bytes      : ");
    dump_hex_single_line(packet, wire_len);
    printf("\n===========================\n");
}

void mdns_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
    mdns_packet mdns;
    int offset = 0;
    offset += parse_ethernet_header(packet, header->len, &mdns.udp.ether);
    int ip_ret = parse_ip_header(packet + offset, header->len - offset, &mdns.udp.ip);
    if (ip_ret < 0 || mdns.udp.ip.protocol != 17) {
        return;
    }
    offset += ip_ret;
    int udp_ret = parse_udp_header(packet + offset, header->len - offset, &mdns.udp);
    if (udp_ret < 0) {
        // Ne rien faire, ce n'est pas un paquet UDP valide
        return;
    }
    offset += udp_ret;
    uint16_t sport = mdns.udp.src_port;
    uint16_t dport = mdns.udp.dst_port;
    if (sport != 5353 && dport != 5353) {
        // Optionnel : fprintf(stderr, "Not an mDNS packet\n");
        return;
    }
    const unsigned char *payload = packet + offset;
    int payload_len = mdns.udp.data_len;
    if (parse_mdns_packet(payload, payload_len, &mdns) == 0) {
        print_mdns_packet(packet, header->len, &mdns);
    }
}