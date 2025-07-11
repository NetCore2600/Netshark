#include "handler.h"
#include "netshark.h"
#include "parser.h"

// Callback pour la capture
void tcp_handler(unsigned char *args, const struct netshark_pkthdr *header, const unsigned char *packet) {
    (void)args; // Just pass the warnings because its not used at all within the function

    eth_header *eth;
    ip_header *ip;
    tcp_header *tcp;
    char flag_str[20];
    int size_ip;
    int size_tcp;
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

    // Vérifier si c'est un paquet TCP
    if (ip->ip_p != IPPROTO_TCP) {
        return;
    }

    // Pointeur vers l'en-tête TCP
    tcp = (tcp_header *)(packet + sizeof(eth_header) + size_ip);
    size_tcp = ((tcp->th_offx2 & 0xf0) >> 4) * 4;

    // Convertir les adresses IP en chaînes
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Obtenir les flags TCP
    get_tcp_flags(tcp->th_flags, flag_str);

    // Afficher les informations détaillées du paquet TCP
    printf("\n=== TCP Packet Analysis ===\n");
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    printf("Source Port: %d\n", ntohs(tcp->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp->th_dport));
    printf("Sequence Number: %u\n", ntohl(tcp->th_seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp->th_ack));
    printf("Window Size: %d\n", ntohs(tcp->th_win));
    printf("TCP Flags: %s\n", flag_str);
    printf("Header Length: %d bytes\n", size_tcp);
    printf("Data Length: %d bytes\n", ntohs(ip->ip_len) - size_ip - size_tcp);
    printf("Total Packet Length: %d bytes\n", header->len);
    printf("==========================\n");
}