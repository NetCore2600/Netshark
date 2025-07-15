#ifndef MDNS_H
#define MDNS_H

#include "udp.h"

#define MDNS_MAX_NAME_LEN 256

typedef struct {
    udp_packet udp;
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
    char qname[MDNS_MAX_NAME_LEN];
    uint16_t qtype, qclass;
    uint16_t total_len;
} mdns_packet;

int parse_mdns_packet(const unsigned char *data, size_t len, mdns_packet *out);
void print_mdns_packet(const unsigned char *packet, uint32_t wire_len, const mdns_packet *mdns);
void mdns_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void print_dns_answers(const unsigned char *data, size_t len, size_t offset, uint16_t ancount);
#endif // MDNS_H