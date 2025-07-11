#include "handler.h"
#include "netshark.h"
#include "parser.h"

void udp_handler(unsigned char *args, const struct netshark_pkthdr *header, const unsigned char *packet) {
    (void)args; // Pour éviter le warning du paramètre non utilisé
    
    eth_header *eth;
    ip_header *ip;
    udp_header *udp;
    int size_ip;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Pointeur vers l'en-tête Ethernet
    eth = (eth_header *)packet;

    // Vérifier si c'est un paquet IP
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // Pointeur vers l'en-tête IP
    ip = (ip_header *)(packet + sizeof(eth_header));
    size_ip = (ip->ip_vhl & 0x0f) * 4;

    // Vérifier si c'est un paquet UDP
    if (ip->ip_p != IPPROTO_UDP) {
        return;
    }

    // Pointeur vers l'en-tête UDP
    udp = (udp_header *)(packet + sizeof(eth_header) + size_ip);

    // Convertir les adresses IP en chaînes
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Afficher les informations détaillées du paquet UDP
    printf("\n=== UDP Packet Analysis ===\n");
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    printf("Source Port: %u\n", ntohs(udp->uh_sport));
    printf("Destination Port: %u\n", ntohs(udp->uh_dport));
    printf("Length: %u bytes\n", ntohs(udp->uh_ulen));
    printf("Checksum: 0x%04x\n", ntohs(udp->uh_sum));
    printf("Data Length: %zu bytes\n", ntohs(udp->uh_ulen) - sizeof(udp_header));
    printf("Total Packet Length: %u bytes\n", header->len);

    // Identification des services courants
    printf("\nService Analysis:\n");
    uint16_t src_port = ntohs(udp->uh_sport);
    uint16_t dst_port = ntohs(udp->uh_dport);

    if (src_port == 53 || dst_port == 53)
        printf("- DNS Service detected\n");
    if (src_port == 67 || dst_port == 67 || src_port == 68 || dst_port == 68)
        printf("- DHCP Service detected\n");
    if (src_port == 123 || dst_port == 123)
        printf("- NTP Service detected\n");
    if (src_port == 161 || dst_port == 161 || src_port == 162 || dst_port == 162)
        printf("- SNMP Service detected\n");

    printf("==========================\n");

    // Appeler le parser UDP pour un traitement plus détaillé
    parse_udp_packet((const unsigned char *)udp, ntohs(udp->uh_ulen));
}