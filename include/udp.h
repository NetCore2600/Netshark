#ifndef UDP_H
#define UDP_H

#include "netshark.h"
#include "ethernet.h"
#include "ip.h"

/*** STRUCTURE DEFINITIONS ***/
typedef struct _udp_header {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
} udp_header;

typedef struct {
    eth_header ether;
    ip_header ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    uint16_t data_len;
    char service_str[64];
} udp_packet;

/*** PROTOTYPES ***/
void udp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_udp_header(const unsigned char *frame, size_t frame_len, udp_packet *out);
void print_udp_packet(const unsigned char *packet, uint32_t wire_len, const udp_packet *p);

#endif /* UDP_H */
