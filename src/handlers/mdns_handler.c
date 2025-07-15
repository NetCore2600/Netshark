#include "mdns.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int parse_mdns_qname(const unsigned char *data, size_t len, size_t *offset, char *out) {
    size_t i = *offset;
    size_t out_i = 0;
    while (i < len && data[i] != 0) {
        uint8_t label_len = data[i++];
        if (label_len == 0 || label_len + i > len || out_i + label_len + 1 >= MDNS_MAX_NAME_LEN)
            return -1;
        memcpy(&out[out_i], &data[i], label_len);
        out_i += label_len;
        i += label_len;
        out[out_i++] = '.';
    }
    if (i >= len || out_i == 0)
        return -1;
    out[out_i - 1] = '\0';
    *offset = i + 1;
    return 0;
}

int parse_mdns_packet(const unsigned char *data, size_t len, mdns_packet *out) {
    if (!data || len < 12 || !out) return -1;
    out->id = ntohs(*(uint16_t *)(data));
    out->flags = ntohs(*(uint16_t *)(data + 2));
    out->qdcount = ntohs(*(uint16_t *)(data + 4));
    out->ancount = ntohs(*(uint16_t *)(data + 6));
    out->nscount = ntohs(*(uint16_t *)(data + 8));
    out->arcount = ntohs(*(uint16_t *)(data + 10));
    size_t offset = 12;
    if (out->qdcount > 0 && parse_mdns_qname(data, len, &offset, out->qname) == 0) {
        if (offset + 4 > len) return -1;
        out->qtype = ntohs(*(uint16_t *)(data + offset));
        out->qclass = ntohs(*(uint16_t *)(data + offset + 2));
    }
    out->total_len = len;
    return 0;
}

void print_mdns_packet(const unsigned char *packet, uint32_t wire_len, const mdns_packet *mdns) {
    printf("=================== mDNS Packet ===================\n");
    printf("Src MAC        : %s\n", mdns->udp.ether.src_mac);
    printf("Dst MAC        : %s\n", mdns->udp.ether.dst_mac);
    printf("Ethertype      : 0x%04x\n\n", mdns->udp.ether.ethertype);
    printf("Source IP      : %s\n", mdns->udp.ip.src);
    printf("Destination IP : %s\n\n", mdns->udp.ip.dst);
    printf("Source Port    : %u\n", mdns->udp.src_port);
    printf("Dest Port      : %u\n\n", mdns->udp.dst_port);
    printf("Transaction ID : 0x%04x\n", mdns->id);
    printf("Flags          : 0x%04x\n", mdns->flags);
    printf("Questions      : %u\n", mdns->qdcount);
    printf("Answers        : %u\n", mdns->ancount);
    printf("Authority RRs  : %u\n", mdns->nscount);
    printf("Additional RRs : %u\n", mdns->arcount);
    if (mdns->qdcount > 0) {
        printf("\n--- Questions ---\n");
        printf("  [1] Name : %s\n", mdns->qname);
        printf("      Type : %u   Class : %u\n", mdns->qtype, mdns->qclass);
    }
    printf("\nRaw Bytes: ");
    dump_hex_single_line(packet, wire_len);
    printf("\n");
}

// Helper pour parser un QNAME avec compression DNS
int parse_dns_name(const unsigned char *data, size_t len, size_t *offset, char *out, size_t outlen) {
    size_t i = *offset, out_i = 0;
    int jumped = 0;
    //size_t jump_offset = 0;
    while (i < len) {
        uint8_t label_len = data[i];
        if (label_len == 0) {
            if (!jumped) *offset = i + 1;
            if (out_i > 0) out[out_i - 1] = '\0';
            else out[0] = '\0';
            return 0;
        }
        if ((label_len & 0xC0) == 0xC0) { // compression
            size_t ptr = ((label_len & 0x3F) << 8) | data[i + 1];
            if (!jumped) *offset = i + 2;
            i = ptr;
            jumped = 1;
            continue;
        }
        i++;
        if (i + label_len > len || out_i + label_len + 1 >= outlen) return -1;
        memcpy(&out[out_i], &data[i], label_len);
        out_i += label_len;
        out[out_i++] = '.';
        i += label_len;
    }
    return -1;
}

// Parsing des records Answer (PTR/SRV)
void print_dns_answers(const unsigned char *data, size_t len, size_t offset, uint16_t ancount) {
    if (ancount > 0) printf("\n--- Answers ---\n");
    for (uint16_t i = 0; i < ancount; i++) {
        char name[256] = {0};
        size_t name_offset = offset;
        if (parse_dns_name(data, len, &name_offset, name, sizeof(name)) != 0) break;
        if (name_offset + 10 > len) break;
        uint16_t type = ntohs(*(uint16_t *)(data + name_offset));
        uint16_t class = ntohs(*(uint16_t *)(data + name_offset + 2));
        uint32_t ttl = ntohl(*(uint32_t *)(data + name_offset + 4));
        uint16_t rdlen = ntohs(*(uint16_t *)(data + name_offset + 8));
        size_t rdata_offset = name_offset + 10;
        const char *type_str = (type == 12) ? "PTR" : (type == 33) ? "SRV" : "OTHER";
        printf("  [%u] Name : %s\n", i+1, name);
        printf("      Type : %s (%u)   Class : %u   TTL : %u\n", type_str, type, class, ttl);
        if (type == 12) { // PTR
            char target[256] = {0};
            size_t ptr_offset = rdata_offset;
            if (parse_dns_name(data, len, &ptr_offset, target, sizeof(target)) == 0) {
                printf("      PTR Target : %s\n", target);
            }
        } else if (type == 33) { // SRV
            if (rdata_offset + 6 > len) continue;
            uint16_t priority = ntohs(*(uint16_t *)(data + rdata_offset));
            uint16_t weight = ntohs(*(uint16_t *)(data + rdata_offset + 2));
            uint16_t port = ntohs(*(uint16_t *)(data + rdata_offset + 4));
            char target[256] = {0};
            size_t srv_offset = rdata_offset + 6;
            if (parse_dns_name(data, len, &srv_offset, target, sizeof(target)) == 0) {
                printf("      SRV Target : %s\n", target);
                printf("      Port : %u   Priority : %u   Weight : %u\n", port, priority, weight);
            }
        }
        offset = rdata_offset + rdlen;
    }
    printf("===================================================\n");
}

void mdns_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
    mdns_packet mdns;
    int offset = 0;
    offset += parse_ethernet_header(packet, header->len, &mdns.udp.ether);
    offset += parse_ip_header(packet + offset, header->len - offset, &mdns.udp.ip);

    // Ajoute ce test :
    if (mdns.udp.ip.protocol != 17) { // 17 = UDP
        // Optionnel : fprintf(stderr, "Not a UDP packet => Protocol %d\n", mdns.udp.ip.protocol);
        return;
    }

    offset += parse_udp_header(packet + offset, header->len - offset, &mdns.udp);
    uint16_t sport = mdns.udp.src_port;
    uint16_t dport = mdns.udp.dst_port;
    if (sport != 5353 && dport != 5353) {
        fprintf(stderr, "Not an mDNS packet\n");
        return;
    }
    const unsigned char *payload = packet + offset;
    int payload_len = mdns.udp.data_len;
    if (parse_mdns_packet(payload, payload_len, &mdns) == 0) {
        print_mdns_packet(packet, header->caplen, &mdns);
        if (mdns.ancount > 0) {
            size_t ans_offset = 12;
            // Avance après toutes les questions
            for (uint16_t i = 0; i < mdns.qdcount; i++) {
                char tmp_name[256];
                parse_dns_name(payload, payload_len, &ans_offset, tmp_name, sizeof(tmp_name));
                ans_offset += 4; // QTYPE + QCLASS
            }
            print_dns_answers(payload, payload_len, ans_offset, mdns.ancount);
        }
    } else {
        fprintf(stderr, "Failed to parse mDNS packet.\n");
    }
}