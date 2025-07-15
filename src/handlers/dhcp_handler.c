#include "dhcp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int parse_dhcp_packet(const unsigned char *data, size_t len, dhcp_packet *out) {
    if (!data || len < 240 || !out) return -1;

    out->op = data[0];
    out->htype = data[1];
    out->hlen = data[2];
    out->hops = data[3];
    out->xid = ntohl(*(uint32_t *)(data + 4));
    out->secs = ntohs(*(uint16_t *)(data + 8));
    out->flags = ntohs(*(uint16_t *)(data + 10));
    out->ciaddr = *(uint32_t *)(data + 12);
    out->yiaddr = *(uint32_t *)(data + 16);
    out->siaddr = *(uint32_t *)(data + 20);
    out->giaddr = *(uint32_t *)(data + 24);

    mac_to_str((const uint8_t *)(data + 28), (char *)out->chaddr, sizeof(out->chaddr));
    memcpy(out->sname, data + 44, 64);
    memcpy(out->file, data + 108, 128);
    memcpy(out->options, data + 240, len - 240);

    out->total_len = len;

    return 0;
}

void print_dhcp_packet(const unsigned char *packet, uint32_t wire_len, const dhcp_packet *p) {
    printf("=== DHCP Packet ===");
    printf("Src MAC        : %s\n", p->udp.ether.src_mac);
    printf("Dst MAC        : %s\n", p->udp.ether.dst_mac);
    printf("Ethertype      : 0x%04x\n\n", p->udp.ether.ethertype);

    printf("Source IP      : %s\n", p->udp.ip.src);
    printf("Destination IP : %s\n\n", p->udp.ip.dst);

    printf("Source Port    : %u\n", p->udp.src_port);
    printf("Dest Port      : %u\n\n", p->udp.dst_port);

    printf("OP Code        : %u (%s)\n", p->op, (p->op == 1 ? "BOOTREQUEST" : "BOOTREPLY"));
    printf("Transaction ID : 0x%08x\n", p->xid);
    printf("Client MAC     : %s\n", p->chaddr);
    printf("Your IP Addr   : %s\n", inet_ntoa(*(struct in_addr *)&p->yiaddr));
    printf("Server IP Addr : %s\n", inet_ntoa(*(struct in_addr *)&p->siaddr));
    printf("Gateway IP     : %s\n", inet_ntoa(*(struct in_addr *)&p->giaddr));

    // Show magic cookie and options (simplified)
    if (memcmp(p->options, "\x63\x82\x53\x63", 4) == 0) {
        printf("Magic Cookie   : 63 82 53 63 (DHCP)\n");

        uint8_t *opt_ptr = (uint8_t *)(p->options + 4);
        while (*opt_ptr != 0xFF) {
            uint8_t code = *opt_ptr++;
            uint8_t len = *opt_ptr++;
            printf("Option %u (%u bytes)\n", code, len);
            opt_ptr += len;
        }
    }

    printf("\nRaw Bytes      : ");
    dump_hex_single_line(packet, wire_len);
    printf("\n===========================\n");
}

void dhcp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;

    dhcp_packet p;
    int offset = 0;

    offset += parse_ethernet_header(packet, header->len, &p.udp.ether);
    offset += parse_ip_header(packet + offset, header->len - offset, &p.udp.ip);
    offset += parse_udp_header(packet + offset, header->len - offset, &p.udp);

    uint16_t sport = p.udp.src_port;
    uint16_t dport = p.udp.dst_port;

    if ((sport != DHCP_CLIENT_PORT && sport != DHCP_SERVER_PORT) &&
        (dport != DHCP_CLIENT_PORT && dport != DHCP_SERVER_PORT)) {
        fprintf(stderr, "Not a DHCP packet\n");
        return;
    }

    const unsigned char *payload = packet + offset;
    int payload_len = p.udp.data_len;

    if (payload_len > 0 && parse_dhcp_packet(payload, payload_len, &p) == 0) {
        print_dhcp_packet(packet, header->len, &p);
    } else {
        fprintf(stderr, "Failed to parse DHCP payload\n");
    }
}
