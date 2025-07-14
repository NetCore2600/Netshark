#ifndef ICMP_H
#define ICMP_H

#include "netshark.h"
#include "ip.h"  // Assume you have IP parsing logic
#include "ethernet.h"  // Assume you have Ethernet parsing logic

/*** MACROS ***/
#define ICMP_ECHO_REPLY             0
#define ICMP_DEST_UNREACHABLE       3
#define ICMP_SOURCE_QUENCH          4
#define ICMP_REDIRECT               5
#define ICMP_ECHO_REQUEST           8
#define ICMP_TIME_EXCEEDED         11
#define ICMP_PARAMETER_PROBLEM     12
#define ICMP_TIMESTAMP             13
#define ICMP_TIMESTAMP_REPLY       14

/*** STRUCTURE DEFINITIONS ***/
typedef struct {
    eth_header ether;
    ip_header ip;

    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;

    uint8_t payload[1024]; // Up to you to truncate/limit this
    uint16_t payload_len;
} icmp_packet;

/*** PROTOTYPES ***/
void icmp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_icmp_packet(const unsigned char *packet, size_t len, icmp_packet *out);
void print_icmp_packet(const unsigned char *packet, uint32_t wire_len, const icmp_packet *icmp);

#endif /* ICMP_H */
