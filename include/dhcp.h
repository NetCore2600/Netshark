#ifndef DHCP_H
#define DHCP_H

#include "udp.h"  // Assuming you have a similar layered structure

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

/*** DHCP Packet Structure (Based on RFC 2131) ***/
typedef struct {
    udp_packet udp;               // Encapsulated UDP packet (contains IP, Ethernet info)

    uint8_t op;                   // Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t htype;                // Hardware address type: 1 = Ethernet
    uint8_t hlen;                 // Hardware address length: 6 for MAC
    uint8_t hops;                 // Hops: used by relay agents (usually 0)

    uint32_t xid;                 // Transaction ID: random number chosen by client
    uint16_t secs;                // Seconds elapsed since client began address acquisition
    uint16_t flags;               // Flags: bit 0 = broadcast flag

    uint32_t ciaddr;              // Client IP address (only filled in if client is in BOUND, RENEW, REBINDING state)
    uint32_t yiaddr;              // 'Your' IP address: the IP address offered to the client
    uint32_t siaddr;              // IP address of next server to use in bootstrap
    uint32_t giaddr;              // Gateway IP address (used by relay agents)

    uint8_t chaddr[16];           // Client hardware address (first 6 bytes are MAC, rest are padding)
    char sname[64];               // Optional server host name (null-terminated string)
    char file[128];               // Boot file name (null-terminated string)

    uint8_t options[312];        // Optional parameters field (DHCP options in TLV format)

    uint16_t total_len;          // Total parsed length of the DHCP message (computed field, not from the wire)
} dhcp_packet;


/*** Prototypes ***/
void dhcp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_dhcp_packet(const unsigned char *data, size_t len, dhcp_packet *out);
void print_dhcp_packet(const unsigned char *packet, uint32_t wire_len, const dhcp_packet *p);

#endif
