#include "parser.h"
#include "handler.h"

void parse_udp_packet(const unsigned char *packet, size_t packet_len) {
    if (packet_len < sizeof(struct _udp_header)) {
        return;
    }

    struct _udp_header *udp = (struct _udp_header *)packet;
    print_udp_header(udp);
}

void print_udp_header(const struct _udp_header *udp) {
    if (udp) {
        printf("Source Port: %u\n", ntohs(udp->uh_sport));
        printf("Destination Port: %u\n", ntohs(udp->uh_dport));
        printf("Length: %u\n", ntohs(udp->uh_ulen));
        printf("Checksum: 0x%04x\n", ntohs(udp->uh_sum));
    }
}
