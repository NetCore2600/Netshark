#include "handler.h"
#include "netcore.h"
#include "parser.h"

void http_handler(const struct pcap_pkthdr *header, const unsigned char *packet) {
    eth_header *eth;
    ip_header *ip;
    http_header *http;
    int size_ip;
    int size_http;
    const unsigned char *payload;
    int payload_len;

    printf("\nDEBUT\n");

    eth = (eth_header *)packet;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    ip = (ip_header *)(packet + sizeof(eth_header));
    size_ip = (ip->ip_vhl & 0x0f) * 4;

    if (ip->ip_p != IPPROTO_TCP)
        return;

    http = (http_header *)(packet + sizeof(eth_header) + size_ip);
    size_http = ((http->th_offx2 & 0xf0) >> 4) * 4;

    uint16_t sport = ntohs(http->th_sport);
    uint16_t dport = ntohs(http->th_dport); 
    if (sport != 80 && dport != 80 && sport != 8080 && dport != 8080)
        return;

    payload = (u_char *)(packet + sizeof(eth_header) + size_ip + size_http);
    payload_len = ntohs(ip->ip_len) - size_ip - size_http;
    printf("HTTP packet received\n");
    http_parse(ip, http, payload, payload_len);
}