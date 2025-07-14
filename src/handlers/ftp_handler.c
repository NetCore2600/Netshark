#include "ftp.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

void parse_ftp_packet(const unsigned char *data, size_t len, ftp_packet *pkt) {
    if (!data || !pkt || len == 0) return;

    size_t copy_len = len < sizeof(pkt->raw) - 1 ? len : sizeof(pkt->raw) - 1;
    memcpy(pkt->raw, data, copy_len);
    pkt->raw[copy_len] = '\0';

    // Detect if it's a response or command
    if (isdigit(pkt->raw[0]) && isdigit(pkt->raw[1]) && isdigit(pkt->raw[2]) && pkt->raw[3] == ' ') {
        pkt->is_response = 1;
        sscanf(pkt->raw, "%d %[^\r\n]", &pkt->response_code, pkt->message);
    } else {
        pkt->is_response = 0;
        sscanf(pkt->raw, "%7s %[^\r\n]", pkt->command, pkt->arguments);
    }
}


void print_ftp_packet(const unsigned char *frame, uint32_t wire_len, const ftp_packet *pkt) {
    puts("\n=== FTP Packet =============");
    printf("Src MAC             : %s\n", pkt->tcp.ether.src_mac);
    printf("Dst MAC             : %s\n", pkt->tcp.ether.dst_mac);
    printf("Ethertype           : 0x%04x\n", pkt->tcp.ether.ethertype);
    puts("");
    printf("Src IP              : %s\n", pkt->tcp.ip.src);
    printf("Dst IP              : %s\n", pkt->tcp.ip.dst);
    puts("");
    printf("Src Port            : %u\n", pkt->tcp.src_port);
    printf("Dst Port            : %u\n", pkt->tcp.dst_port);
    printf("Seq Number          : %u\n", pkt->tcp.seq_num);
    printf("Ack Number          : %u\n", pkt->tcp.ack_num);
    printf("Flags               : %s\n", pkt->tcp.flags_str);
    printf("Window Size         : %u\n", pkt->tcp.window);
    printf("Header Length       : %u bytes\n", pkt->tcp.header_len);
    printf("Data Length         : %u bytes\n", pkt->tcp.data_len);
    puts("");
    if (pkt->is_response) {
        printf("Response Code       : %d\n", pkt->response_code);
        printf("Message             : %s\n", pkt->message);
    } else {
        printf("Command         : %s\n", pkt->command);
        printf("Arguments       : %s\n", pkt->arguments);
    }
    puts("");
    printf("Total on wire       : %u bytes\n", wire_len);
    printf("Raw Bytes           : "); dump_hex_single_line(frame, wire_len);
    puts("\n===========================\n");
}


void ftp_handler(
    unsigned char *user,
    const struct pcap_pkthdr *hdr,
    const unsigned char *packet
) {
    (void)user;
    ftp_packet pkt;
    int offset = 0;

    offset += parse_ethernet_header(packet, hdr->len, &pkt.tcp.ether);
    offset += parse_ip_header(packet + offset, hdr->len - offset, &pkt.tcp.ip);
    offset += parse_tcp_header(packet + offset, hdr->len - offset, &pkt.tcp);

    // Parse only if port matches FTP control port
    if (pkt.tcp.src_port != FTP_PORT && pkt.tcp.dst_port != FTP_PORT)
        return;

    const unsigned char *payload = packet + offset;
    int payload_len = pkt.tcp.data_len;
    if (payload_len > 0) {
        parse_ftp_packet(payload, payload_len, &pkt);
        print_ftp_packet(packet, hdr->len, &pkt);
    }
}
