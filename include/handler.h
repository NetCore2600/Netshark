#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include "netcore.h"




/***********************************|
|              MACRO                |
|__________________________________*/




/***********************************|
|            STRUCTURE              |
|__________________________________*/

// TCP
typedef struct  _tcp_header {
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_offx2;
    unsigned char th_flags;
    unsigned short th_win;
    unsigned short th_sum;
    unsigned short th_urp;
}               tcp_header;


// UDP


// ARP



// FTP



// HTTP





/***********************************|
|            PROTOTYPE              |
|__________________________________*/

void tcp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif /* TCP_PARSER_H */