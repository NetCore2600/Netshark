#ifndef IP_H
# define IP_H

#include <arpa/inet.h>

typedef struct _ip_header {
    unsigned char ip_vhl;     // Version (4 bits) + Header Length (4 bits)
                              //   - ip_vhl >> 4 gives IP version (should be 4 for IPv4)
                              //   - ip_vhl & 0x0F gives header length in 32-bit words (e.g., 5 = 20 bytes)

    unsigned char ip_tos;     // Type of Service (TOS)
                              //   - Prioritization of packet (e.g., low delay, high throughput)
                              //   - Deprecated in favor of DSCP and ECN

    unsigned short ip_len;    // Total Length (in bytes)
                              //   - Entire packet size, including header + data

    unsigned short ip_id;     // Identification
                              //   - Used for uniquely identifying the fragments of a single datagram

    unsigned short ip_off;    // Fragment Offset and Flags
                              //   - Flags: 3 bits (Reserved, Don't Fragment, More Fragments)
                              //   - Offset: 13 bits (position of this fragment in original datagram)

    unsigned char ip_ttl;     // Time To Live
                              //   - Limits the packet's lifetime (number of hops)
                              //   - Decremented at each router, discarded at 0

    unsigned char ip_p;       // Protocol
                              //   - Indicates the next-level protocol (e.g., TCP=6, UDP=17, ICMP=1)

    unsigned short ip_sum;    // Header Checksum
                              //   - Error-checking for the IP header only (not data)

    struct in_addr ip_src;    // Source IP Address (32-bit IPv4 address)
                              //   - The sender's address

    struct in_addr ip_dst;    // Destination IP Address (32-bit IPv4 address)
                              //   - The intended recipient
} ip_header;


#endif // NETCORE_H
