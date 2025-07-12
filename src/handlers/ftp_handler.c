#include "ftp.h"
#include "tcp.h"
#include "netshark.h"
#include "ip.h"
#include "ethernet.h"

void ftp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    (void)args;

    ether_header *eth;
    ip_header *ip;
    tcp_header *tcp;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    time_t now;
    struct tm *timeinfo;
    char time_str[20];
    int ip_header_len;
    int tcp_header_len;
    int payload_len;
    const unsigned char *payload;

    // Récupération de l'heure actuelle
    time(&now);
    timeinfo = localtime(&now);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);

    // Analyse de l'en-tête Ethernet
    eth = (ether_header *)packet;

    // Vérification que c'est bien un paquet IP
    if (ntohs(eth->type_len) != ETHERTYPE_IPV4)
    {
        return;
    }

    // Analyse de l'en-tête IP
    ip = (ip_header *)(packet + sizeof(ether_header));
    ip_header_len = (ip & 0x0F) * 4;

    // Vérification que c'est bien un paquet TCP
    if (ip->ip_p != IPPROTO_TCP)
    {
        return;
    }

    // Analyse de l'en-tête TCP
    tcp = (tcp_header *)(packet + sizeof(ether_header) + ip_header_len);
    tcp_header_len = ((tcp->th_offx2 & 0xf0) >> 4) * 4;

    // Vérification que c'est bien un paquet FTP (port 21)
    if (ntohs(tcp->th_sport) != 21 && ntohs(tcp->th_dport) != 21)
    {
        return;
    }

    // Extraction des données
    payload = (unsigned char *)(packet + sizeof(ether_header) + ip_header_len + tcp_header_len);
    payload_len = header->len - (sizeof(ether_header) + ip_header_len + tcp_header_len);

    // Conversion des adresses IP
    inet_ntop(AF_INET, &(ip->src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dst), dst_ip, INET_ADDRSTRLEN);

    // Affichage des informations de base
    printf("\n[%s] ", time_str);
    printf("FTP %s:%d -> %s:%d\n",
           src_ip, ntohs(tcp->th_sport),
           dst_ip, ntohs(tcp->th_dport));

    // Traitement des données FTP
    if (payload_len > 0)
    {
        parse_ftp_packet(payload, payload_len);
    }
}
