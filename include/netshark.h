#ifndef NETCORE_H
# define NETCORE_H

#include <stdio.h>
#include "netshark.h"
#include "netshark_types.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

/***********************************|
|             STRUCT                |
|__________________________________*/

// Structure personnalisée pour remplacer pcap_t
struct netshark_t {
    int activated;
    int linktype;
    char *errbuf;
    // Autres champs nécessaires pour notre implémentation
};

// Arguments given when launching the program 
typedef struct _Args {
    char *dev;
    char *filter_exp;
}               Args;

// The full context of the application
typedef struct  NetShark {
    // A linked list of all devices from our system
    netshark_if_t *alldevs;
    // The selected device for capture
    netshark_if_t *selected_dev;

    // The is a buffer reserved for the packet handler
    // It is used to store the error/warning messages during capture
    char errbuf[NETSHARK_ERRBUF_SIZE];
    
    // The actual handler function that will be triggered
    // each time a packet is captured
    netshark_t *handle;  // Changé de pcap_t à netshark_t
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

// Fonctions netshark_ pour remplacer les fonctions pcap_
int netshark_findalldevs(netshark_if_t **alldevsp, char *errbuf);
netshark_t *netshark_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
int netshark_datalink(netshark_t *p);
int netshark_compile(netshark_t *p, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask);
const char *netshark_geterr(netshark_t *p);
void netshark_close(netshark_t *p);
void netshark_freealldevs(netshark_if_t *alldevs);
int netshark_setfilter(netshark_t *p, struct bpf_program *fp);
void netshark_freecode(struct bpf_program *fp);
int netshark_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf);
int netshark_loop(netshark_t *p, int cnt, netshark_handler callback, u_char *user);

/***********************************|
|           PROTOTYPE               |
|__________________________________*/

// /src/init.c
void init(NetShark *n, Args args);





#endif /* NETCORE_H */