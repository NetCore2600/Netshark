#ifndef HANDLER_H
#define HANDLER_H

#include "netshark.h"




/***********************************|
|              MACRO                |
|__________________________________*/

#define ARP_REQUEST    1
#define ARP_REPLY      2
#define ARP_HARDWARE_TYPE_ETHERNET 1

/***********************************|
|            STRUCTURE              |
|__________________________________*/


// HandlerPacket structure with void return functions
typedef struct {
    void (*tcp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*udp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*arp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*ftp)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
    void (*http)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
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
typedef struct _udp_header {
    unsigned short uh_sport;
    unsigned short uh_dport;
    unsigned short uh_ulen;
    unsigned short uh_sum;
} udp_header;

// ARP
typedef struct _arp_header {
    unsigned short ar_hrd;    // Format du matériel
    unsigned short ar_pro;    // Format du protocole
    unsigned char ar_hln;     // Longueur de l'adresse matérielle
    unsigned char ar_pln;     // Longueur de l'adresse protocole
    unsigned short ar_op;     // Type d'opération
    unsigned char ar_sha[6];  // Adresse matérielle source
    unsigned char ar_sip[4];  // Adresse IP source
    unsigned char ar_tha[6];  // Adresse matérielle cible
    unsigned char ar_tip[4];  // Adresse IP cible
} arp_header;

// FTP
// Structure pour les commandes FTP
typedef struct {
    char command[5];    // Commande FTP
    char *argument;     // Argument de la commande
} ftp_command;

// Structure pour les réponses FTP
typedef struct {
    int code;          // Code de réponse
    char *message;     // Message de réponse
} ftp_response;

// Structure pour les données FTP
struct ftp_data {
    char command[5];              // Commande FTP
    char argument[256];           // Argument de la commande
    unsigned int code;            // Code de réponse
    char message[512];            // Message de réponse
};


/***********************************|
|            PROTOTYPE              |
|__________________________________*/

// /handlers/tcp_handler.c
void tcp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void get_tcp_flags(unsigned char flags, char *str);

// /handlers/udp_handler.c
void udp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);


// /handlers/arp_handler.c
void arp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);


// /handlers/ftp_handler.c
void ftp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

void http_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);



#endif /* HANDLER_H */