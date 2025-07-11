#include "handler.h"
#include "netshark.h"
#include "parser.h"

void arp_handler(unsigned char *args, const struct netshark_pkthdr *header, const unsigned char *packet) {

    (void)args; // Pour éviter le warning du paramètre non utilisé
    
    eth_header *eth;
    arp_header *arp;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char src_mac[18];
    char dst_mac[18];

    // Pointeur vers l'en-tête Ethernet
    eth = (eth_header *)packet;

    // Vérifier si c'est un paquet ARP
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) {
        return;
    }

    // Pointeur vers l'en-tête ARP
    arp = (arp_header *)(packet + sizeof(eth_header));

    // Convertir les adresses IP en chaînes
    inet_ntop(AF_INET, arp->ar_sip, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp->ar_tip, dst_ip, INET_ADDRSTRLEN);

    // Convertir les adresses MAC en chaînes
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2],
             arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);
    
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->ar_tha[0], arp->ar_tha[1], arp->ar_tha[2],
             arp->ar_tha[3], arp->ar_tha[4], arp->ar_tha[5]);

    // Afficher les informations détaillées du paquet ARP
    printf("\n=== ARP Packet Analysis ===\n");
    printf("Operation: %s\n", ntohs(arp->ar_op) == ARP_REQUEST ? "Request" : "Reply");
    printf("Hardware Type: %s\n", ntohs(arp->ar_hrd) == ARP_HARDWARE_TYPE_ETHERNET ? "Ethernet" : "Unknown");
    printf("Protocol Type: IPv4\n");
    printf("Hardware Size: %d\n", arp->ar_hln);
    printf("Protocol Size: %d\n", arp->ar_pln);
    printf("Source MAC: %s\n", src_mac);
    printf("Source IP: %s\n", src_ip);
    printf("Target MAC: %s\n", dst_mac);
    printf("Target IP: %s\n", dst_ip);
    printf("Total Packet Length: %u bytes\n", header->len);
    printf("==========================\n");

    // Appeler le parser ARP pour un traitement plus détaillé
    parse_arp_packet((const unsigned char *)arp, sizeof(arp_header));
}
