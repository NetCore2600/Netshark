#ifndef TCP_H
#define TCP_H

#include "netshark.h"

/*** MACROS ***/
// TCP Flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20    

/*** STRUCTURE ***/
typedef struct _tcp_header {
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_offx2;
    unsigned char th_flags;
    unsigned short th_win;
    unsigned short th_sum;
    unsigned short th_urp;
} tcp_header;

/*** PROTOTYPES ***/
void tcp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void get_tcp_flags(unsigned char flags, char *str);
void parse_tcp_packet(const unsigned char *packet, size_t packet_len);

#endif /* TCP_H */
