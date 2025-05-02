#ifndef HANDLER_H
#define HANDLER_H

#include "netcore.h"




/***********************************|
|              MACRO                |
|__________________________________*/




/***********************************|
|            STRUCTURE              |
|__________________________________*/


// HandlerPacket structure with void return functions
typedef struct {
    void (*tcp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*udp)(const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*arp)(const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*ftp)(const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*http)(const struct pcap_pkthdr *header, const unsigned char *packet);
} HandlerPacket;


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

// /handlers/tcp_handler.c
void tcp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void get_tcp_flags(unsigned char flags, char *str);








#endif /* HANDLER_H */