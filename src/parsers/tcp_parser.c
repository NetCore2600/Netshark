#include "parser.h"

// Fonction pour obtenir les flags TCP
void get_tcp_flags(unsigned char flags, char *flag_str) {
    flag_str[0] = '\0';
    if (flags & TH_FIN) strcat(flag_str, "FIN ");
    if (flags & TH_SYN) strcat(flag_str, "SYN ");
    if (flags & TH_RST) strcat(flag_str, "RST ");
    if (flags & TH_PUSH) strcat(flag_str, "PSH ");
    if (flags & TH_ACK) strcat(flag_str, "ACK ");
    if (flags & TH_URG) strcat(flag_str, "URG ");
}

void parse_tcp_packet(const unsigned char *packet, size_t packet_len) {
    (void)packet;
    (void)packet_len;
}

void print_tcp_header(const struct _tcp_header *tcp) {
    (void)tcp;
    
}

