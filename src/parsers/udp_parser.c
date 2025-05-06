#include "parser.h"
#include "handler.h"

void parse_udp_packet(const unsigned char *packet, size_t packet_len) {
    if (packet_len < sizeof(struct _udp_header)) {
        return;
    }

    struct _udp_header *udp = (struct _udp_header *)packet;
    
}


