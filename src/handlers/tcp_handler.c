#include "tcp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

void get_tcp_flags(unsigned char flags, char *str) {
    strcpy(str, "");
    if (flags & TH_FIN)  strcat(str, "FIN ");
    if (flags & TH_SYN)  strcat(str, "SYN ");
    if (flags & TH_RST)  strcat(str, "RST ");
    if (flags & TH_PUSH) strcat(str, "PSH ");
    if (flags & TH_ACK)  strcat(str, "ACK ");
    if (flags & TH_URG)  strcat(str, "URG ");
}

int parse_tcp_header(const unsigned char *frame, size_t frame_len, tcp_packet *out) {
    if (!frame || !out)
        return -1;
    if (out->ip.protocol != IPPROTO_TCP)
    {
        fprintf(stderr, "Error not TCP protocol => %d\n", out->ip.protocol);
        return -1;
    }
    if (frame_len < sizeof(tcp_header))
        return -1;

    const tcp_header *tcp = (const tcp_header *)frame;
    int tcp_hdr_len = ((tcp->offx2 & 0xF0) >> 4) * 4;

    if (frame_len < (size_t)tcp_hdr_len)
        return -1;

    out->src_port  = ntohs(tcp->sport);
    out->dst_port  = ntohs(tcp->dport);
    out->seq_num   = ntohl(tcp->seq);
    out->ack_num   = ntohl(tcp->ack);
    out->flags     = tcp->flags;
    out->window    = ntohs(tcp->win);
    out->checksum  = ntohs(tcp->sum);
    out->urg_ptr   = ntohs(tcp->urp);
    out->header_len = tcp_hdr_len;

    // Calculate data length from IP total length
    int total_ip_len = out->ip.total_len;
    out->data_len = total_ip_len - out->ip.header_len - tcp_hdr_len;

    get_tcp_flags(out->flags, out->flags_str);

    // Return total bytes parsed from Ethernet + IP + TCP headers
    return tcp_hdr_len;
}


void print_tcp_packet(const unsigned char *frame, uint32_t wire_len, const tcp_packet *p) {
    puts("\n=== TCP Packet ============");
    printf("Src MAC         : %s\n", p->ether.src_mac);
    printf("Dst MAC         : %s\n", p->ether.dst_mac);
    printf("Ethertype       : 0x%04x\n", p->ether.ethertype);
    puts("");
    printf("Src IP          : %s\n", p->ip.src);
    printf("Dst IP          : %s\n", p->ip.dst);
    puts("");
    printf("Src Port        : %u\n", p->src_port);
    printf("Dst Port        : %u\n", p->dst_port);
    printf("Seq Number      : %u\n", p->seq_num);
    printf("Ack Number      : %u\n", p->ack_num);
    printf("Flags           : %s\n", p->flags_str);
    printf("Window Size     : %u\n", p->window);
    printf("Header Length   : %u bytes\n", p->header_len);
    printf("Data Length     : %u bytes\n", p->data_len);
    puts("");
    printf("Total on wire   : %u bytes\n", wire_len);
    printf("Raw Bytes       : "); dump_hex_single_line(frame, wire_len);
    puts("\n===========================\n");
}

void tcp_handler(
    unsigned char            *user,
    const struct pcap_pkthdr *hdr,
    const unsigned char      *frame
) {
    (void)user;
    tcp_packet pkt;

    int offset = 0;
    offset += parse_ethernet_header(frame + offset, hdr->len - offset, &pkt.ether);
    offset += parse_ip_header(frame + offset, hdr->len - offset, &pkt.ip);
    parse_tcp_header(frame + offset, hdr->len - offset, &pkt);


    print_tcp_packet(frame, hdr->len, &pkt);
}
