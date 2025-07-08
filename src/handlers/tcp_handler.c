#include "tcp.h"
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

int parse_tcp_packet(const unsigned char *frame, size_t frame_len, tcp_packet *out) {
    if (!frame || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    // Parse Ethernet header
    int offset = parse_ethernet_frame(frame, frame_len, &out->ether);
    if (offset < 0 || frame_len < offset + sizeof(ip_header)) {
        fprintf(stderr, "Invalid Ethernet or IP header\n");
        return -1;
    }
    
    frame += offset;

    const ip_header *ip = (const ip_header *)(frame);
    memcpy(&out->ip, ip, sizeof(ip_header));

    if (ip->ip_p != IPPROTO_TCP) return -1;

    int ip_hdr_len = (ip->ip_vhl & 0x0F) * 4;
    if (frame_len < offset + ip_hdr_len + sizeof(tcp_header))
        return -1;

    const tcp_header *tcp = (const tcp_header *)(frame + ip_hdr_len);
    int tcp_hdr_len = ((tcp->th_offx2 & 0xF0) >> 4) * 4;

    out->src_port  = ntohs(tcp->th_sport);
    out->dst_port  = ntohs(tcp->th_dport);
    out->seq_num   = ntohl(tcp->th_seq);
    out->ack_num   = ntohl(tcp->th_ack);
    out->flags     = tcp->th_flags;
    out->window    = ntohs(tcp->th_win);
    out->checksum  = ntohs(tcp->th_sum);
    out->urg_ptr   = ntohs(tcp->th_urp);
    out->header_len = tcp_hdr_len;
    out->data_len = ntohs(ip->ip_len) - ip_hdr_len - tcp_hdr_len;

    inet_ntop(AF_INET, &ip->ip_src, out->src_ip, sizeof(out->src_ip));
    inet_ntop(AF_INET, &ip->ip_dst, out->dst_ip, sizeof(out->dst_ip));

    get_tcp_flags(out->flags, out->flags_str);
    return 0;
}

void print_tcp_packet(const unsigned char *packet, uint32_t wire_len, const tcp_packet *p) {
    puts("\n=== TCP Packet (Parsed) ===");

    printf("Src MAC        : %s\n", p->ether.src_mac);
    printf("Dst MAC        : %s\n", p->ether.dst_mac);
    printf("Ethertype      : 0x%04x\n", ntohs(p->ether.ethertype));

    printf("Source IP      : %s\n", p->src_ip);
    printf("Destination IP : %s\n", p->dst_ip);
    printf("Source Port    : %u\n", p->src_port);
    printf("Destination Port: %u\n", p->dst_port);

    printf("Seq Number     : %u\n", p->seq_num);
    printf("Ack Number     : %u\n", p->ack_num);
    printf("Flags          : %s\n", p->flags_str);
    printf("Window Size    : %u\n", p->window);
    printf("Header Length  : %u bytes\n", p->header_len);
    printf("Data Length    : %u bytes\n", p->data_len);
    printf("Total on wire  : %u bytes\n", wire_len);
    printf("Raw Bytes      : "); dump_hex_single_line(packet, wire_len); printf("\n");

    puts("===========================");
}

void tcp_handler(
    unsigned char            *user,
    const struct pcap_pkthdr *hdr,
    const unsigned char      *packet
) {
    (void)user;

    tcp_packet pkt;
    if (parse_tcp_packet(packet, hdr->len, &pkt) == 0)
        print_tcp_packet(packet, hdr->len, &pkt);
}
