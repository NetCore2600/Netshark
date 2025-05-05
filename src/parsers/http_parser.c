#include "parser.h"
#include "handler.h"


//void parse_http(void) {}
//void print_http(void) {}

void http_parse(ip_header *ip, http_header *http, const u_char *payload, int payload_len) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("\n=== HTTP Packet Analysis ===\n");
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    printf("Source Port: %d\n", ntohs(http->th_sport));
    printf("Destination Port: %d\n", ntohs(http->th_dport));
    printf("Payload Length: %d bytes\n", payload_len);
    printf("Payload: %.*s\n", payload_len, payload);
    printf("============================\n");
}