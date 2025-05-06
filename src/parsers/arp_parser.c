#include "parser.h"
#include "handler.h"

void parse_arp_packet(const unsigned char *packet, size_t packet_len) {
    if (packet_len < sizeof(struct _arp_header)) {
        printf("Paquet ARP trop court\n");
        return;
    }

    struct _arp_header *arp = (struct _arp_header *)packet;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char src_mac[18];
    char dst_mac[18];

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

    
}



