#ifndef DNS_H
#define DNS_H

#include "udp.h"

#define DNS_MAX_NAME_LEN 256
#define DNS_MAX_PACKET_SIZE 512

typedef struct {
    udp_packet udp;

    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    char qname[DNS_MAX_NAME_LEN];
    uint16_t qtype;
    uint16_t qclass;

    uint16_t total_len;
} dns_packet;

int parse_dns_packet(const unsigned char *data, size_t len, dns_packet *out);
void print_dns_packet(const unsigned char *packet, uint32_t wire_len, const dns_packet *dns);
void dns_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif // DNS_H
