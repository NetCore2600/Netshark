#ifndef ARP_H
#define ARP_H

#include "netshark.h"
#include "ethernet.h"
#include <stdint.h>
#include <netinet/in.h>

/*** MACROS ***/
#define ARP_REQUEST                 1
#define ARP_REPLY                   2
#define ARP_HARDWARE_TYPE_ETHERNET 1

/*** STRUCTURE DEFINITIONS ***/
typedef struct _arp_header {
    uint16_t hrd;    // Hardware type
    uint16_t pro;    // Protocol type
    uint8_t  hln;    // Hardware address length
    uint8_t  pln;    // Protocol address length
    uint16_t op;     // Operation code
    uint8_t  sha[6]; // Sender hardware address
    uint8_t  sip[4]; // Sender IP address
    uint8_t  tha[6]; // Target hardware address
    uint8_t  tip[4]; // Target IP address
} arp_header;

typedef struct {
    eth_header ether;

    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_size;
    uint8_t  protocol_size;
    uint16_t operation;

    char sender_mac[ETH_ADDR_STRLEN];
    char sender_ip[INET_ADDRSTRLEN];
    char target_mac[ETH_ADDR_STRLEN];
    char target_ip[INET_ADDRSTRLEN];
} arp_packet;

/*** PROTOTYPES ***/
void arp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_arp_packet(const unsigned char *frame, size_t frame_len, arp_packet *out);
void print_arp_packet(const unsigned char *packet, uint32_t wire_len, const arp_packet *p);

#endif /* ARP_H */
