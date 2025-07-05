#ifndef ETHERNET_H
# define ETHERNET_H

#define ETHERTYPE_IP 0x0800  // Indicates IPv4 protocol
#define ETHERTYPE_ARP 0x0806  // Indicates ARP (Address Resolution Protocol)


// Structures pour les en-têtes
typedef struct  _ether_header {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    unsigned short ether_type;
}               ether_header;

#endif // ETHERNET_H