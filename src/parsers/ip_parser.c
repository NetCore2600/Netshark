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

/* Parses the IP header */
int parse_ip_header(const unsigned char *frame, size_t frame_len, ip_header *out) {
    if (!frame || !out) return -1;
    if (frame_len < sizeof(ip_info)) return -1;

    const ip_info *iph = (const ip_info *)(const void *)frame;

    memset(out, 0, sizeof *out);

    out->version     = iph->vhl >> 4;
    out->header_len  = (iph->vhl & 0x0F) * 4; // in bytes

    if (frame_len < out->header_len) return -1; // truncated IP header

    out->tos         = iph->tos;
    out->total_len   = ntohs(iph->total_len);
    out->id          = ntohs(iph->id);
    out->frag_off    = ntohs(iph->frag_off);
    out->ttl         = iph->ttl;
    out->protocol    = iph->protocol;
    out->checksum    = ntohs(iph->checksum);
    ip_to_str(&iph->src, out->src, sizeof(out->src));
    ip_to_str(&iph->dst, out->dst, sizeof(out->dst));

    return out->header_len; // offset to next protocol layer (e.g., TCP)
}