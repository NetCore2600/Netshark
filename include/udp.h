#ifndef UDP_H
# define UDP_H

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
    ether ether;                    // Ethernet header
    ip_header ip;                   // IP header
    uint16_t src_port;              // Source port
    uint16_t dst_port;              // Destination port
    uint16_t length;                // Length field
    uint16_t checksum;              // UDP checksum
    uint16_t data_len;              // UDP payload length

    char service_str[64];           // Service hint (DNS, DHCP, etc.)
} udp_packet;

/*** PROTOTYPES ***/
void udp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_udp_packet(const unsigned char *frame, size_t frame_len, udp_packet *out);
void print_udp_packet(const unsigned char *packet, uint32_t wire_len, const udp_packet *p);

#endif /* UDP_H */
