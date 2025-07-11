#include "ip.h"
#include <stdio.h>
#include <string.h>

/* Format an IP address into dotted-decimal string */
static void ip_to_str(const struct in_addr *addr, char *dst, size_t dst_len) {
    if (!addr || !dst || dst_len < INET_ADDRSTRLEN) {
        if (dst && dst_len > 0) dst[0] = '\0';
        return;
    }
    inet_ntop(AF_INET, addr, dst, dst_len);
}

/* Output structure for parsed IP data */



/* Parses the IP header */
int parse_ip_header(const unsigned char *packet, size_t packet_len, ip_header *out) {
    if (!packet || !out) return -1;
    if (packet_len < sizeof(ip_info)) return -1;

    const ip_info *iph = (const ip_info *)(const void *)packet;

    memset(out, 0, sizeof *out);

    out->version     = iph->version >> 4;
    out->header_len  = (iph->version & 0x0F) * 4; // in bytes

    if (packet_len < out->header_len) return -1; // truncated IP header

    out->tos         = iph->tos;
    out->total_len   = ntohs(iph->total_len);
    out->id          = ntohs(iph->id);
    out->frag_off    = ntohs(iph->frag_off);
    out->ttl         = iph->ttl;
    out->protocol    = iph->protocol;
    out->checksum    = ntohs(iph->checksum);

    ip_to_str(&iph->src_ip, out->src.s_addr, sizeof out->src.s_addr);
    ip_to_str(&iph->dst_ip, out->dst.s_addr, sizeof out->src.s_addr);

    return (int)out->header_len; // offset to next protocol layer (e.g., TCP)
}