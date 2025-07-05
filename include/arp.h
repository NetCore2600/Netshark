#ifndef ARP_H
#define ARP_H

#include "netshark.h"

/*** MACROS ***/
#define ARP_REQUEST                 1
#define ARP_REPLY                   2
#define ARP_HARDWARE_TYPE_ETHERNET 1

/*** STRUCTURE ***/
typedef struct _arp_header {
    unsigned short ar_hrd;
    unsigned short ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    unsigned short ar_op;
    unsigned char ar_sha[6];
    unsigned char ar_sip[4];
    unsigned char ar_tha[6];
    unsigned char ar_tip[4];
} arp_header;

typedef struct arp_packet {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char src_mac[18];
    char dst_mac[18];
    uint16_t operation;
    uint16_t hardware_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t protocol_type;
} arp_packet;

/*** PROTOTYPES ***/
void arp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void parse_arp_packet(const unsigned char *packet, size_t packet_len);

#endif /* ARP_H */
