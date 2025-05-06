#ifndef NETCORE_H
# define NETCORE_H

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/types.h>

/***********************************|
|             STRUCT                |
|__________________________________*/

// Arguments given when launching the program 
typedef struct _Args {
    char *dev;
    char *filter_exp;
}               Args;

// The full context of the application
typedef struct  NetShark {
    // A linked list of all devices from our system
    pcap_if_t *alldevs;
    // The selected device for capture
    pcap_if_t *selected_dev;

    // The is a buffer reserved for the packet handler
    // It is used to store the error/warning messages during capture
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // The actual handler function that will be triggered
    // each time a packet is captured
    pcap_t *handle;
    void *handler;
    struct bpf_program fp;
    bpf_u_int32 net;
}               NetShark;

// Structures pour les en-têtes
typedef struct _eth_header {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    unsigned short ether_type;
}              eth_header;

typedef struct  _ip_header {
    unsigned char ip_vhl;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
}               ip_header;





/***********************************|
|           PROTOTYPE               |
|__________________________________*/

// /src/init.c
void init(NetShark *n, Args args);





#endif /* NETCORE_H */