#ifndef IP_H
# define IP_H

#include <arpa/inet.h>

typedef struct _ip_info {
    uint8_t  vhl;         // Version (4 bits) | Header Length (4 bits)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    struct in_addr src;
    struct in_addr dst;
} ip_info;



typedef struct _ip_header {
    unsigned char version;      // Version (4 bits) + Header Length (4 bits)
                                //   - ip_vhl >> 4 gives IP version (should be 4 for IPv4)
                                //   - ip_vhl & 0x0F gives header length in 32-bit words (e.g., 5 = 20 bytes)
    unsigned char header_len;   // Version (4 bits) + Header Length (4 bits)
                                //   - ip_vhl >> 4 gives IP version (should be 4 for IPv4)
                                //   - ip_vhl & 0x0F gives header length in 32-bit words (e.g., 5 = 20 bytes)

    unsigned char tos;          // Type of Service (TOS)
                                //   - Prioritization of packet (e.g., low delay, high throughput)
                                //   - Deprecated in favor of DSCP and ECN

    unsigned short total_len;   // Total Length (in bytes)
                                //   - Entire packet size, including header + data

    unsigned short id;          // Identification
                                //   - Used for uniquely identifying the fragments of a single datagram

    unsigned short frag_off;    // Fragment Offset and Flags
                                //   - Flags: 3 bits (Reserved, Don't Fragment, More Fragments)
                                //   - Offset: 13 bits (position of this fragment in original datagram)

    unsigned char ttl;          // Time To Live
                                //   - Limits the packet's lifetime (number of hops)
                                //   - Decremented at each router, discarded at 0

    unsigned char protocol;     // Protocol
                                //   - Indicates the next-level protocol (e.g., TCP=6, UDP=17, ICMP=1)

    unsigned short checksum;    // Header Checksum
                                //   - Error-checking for the IP header only (not data)

                                //   - The intended recipient
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
} ip_header;

int parse_ip_header(const unsigned char *, size_t, ip_header *);

#endif // NETCORE_H
