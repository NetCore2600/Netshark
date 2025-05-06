#include "parser.h"
#include "handler.h"


void parse_udp_packet(const unsigned char *packet, int packet_len) {
    if (packet_len < sizeof(struct _udp_header)) {
        return;
    }

    struct _udp_header *udp = (struct _udp_header *)packet;
    
}

void print_udp_header(const struct _udp_header *udp) {
    // Cette fonction est maintenant vide car l'affichage est géré par le handler
    (void)udp;
}
