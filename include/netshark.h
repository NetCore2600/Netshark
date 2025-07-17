#ifndef NETSHARK_H
# define NETSHARK_H

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>


extern int DEBUG_MODE;


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

typedef struct {
    void (*tcp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*udp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*arp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*ftp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*http)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*icmp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*dhcp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*dns)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*mdns)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*tls)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
} HandlerPacket;





/***********************************|
|           PROTOTYPE               |
|__________________________________*/

// /src/init.c
void init(NetShark *n, Args args);

// /src/utils.c
void dump_hex_single_line(const uint8_t *buf, size_t len);
void mac_to_str(const uint8_t mac[6], char *dst, size_t dstframe_len);


#endif /* NETSHARK_H */