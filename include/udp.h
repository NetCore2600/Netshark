#ifndef UDP_H
#define UDP_H

#include "netshark.h"

/*** MACROS ***/
// UDP Field Flags
#define UDP_SOURCE_PORT 0x0001
#define UDP_DEST_PORT   0x0002
#define UDP_LENGTH      0x0004
#define UDP_CHECKSUM    0x0008

/*** STRUCTURE ***/
typedef struct _udp_header {
    unsigned short uh_sport;
    unsigned short uh_dport;
    unsigned short uh_ulen;
    unsigned short uh_sum;
} udp_header;

/*** PROTOTYPES ***/
void udp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void parse_udp_packet(const unsigned char *packet, size_t packet_len);

#endif /* UDP_H */
