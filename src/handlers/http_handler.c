#include "http.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

int parse_http_packet(const unsigned char *data, size_t len, http_packet *out) {
    if (!data || !out || len == 0) return -1;

    const char *start = (const char *)data;
    const char *end = start + len;

    // Detect if response or request
    if (strncmp(start, "HTTP/", 5) == 0) {
        out->is_response = 1;
        sscanf(start, "%15s %d %[^\r\n]", out->version, &out->status_code, out->status_message);
    } else {
        out->is_request = 1;
        sscanf(start, "%15s %255s %15s", out->method, out->path, out->version);
    }

    // Locate headers
    const char *headers_start = strstr(start, "\r\n");
    if (!headers_start) return 0;
    headers_start += 2;

    const char *body_start = strstr(headers_start, "\r\n\r\n");
    if (body_start) {
        out->header_len = body_start + 4 - start;

        size_t headers_len = body_start - headers_start;
        if (headers_len < sizeof(out->headers)) {
            memcpy(out->headers, headers_start, headers_len);
            out->headers[headers_len] = '\0';
        }

        body_start += 4;
        size_t body_len = end - body_start;
        out->data_len = body_len < sizeof(out->body) ? body_len : sizeof(out->body) - 1;
        memcpy(out->body, body_start, out->data_len);
        out->body[out->data_len] = '\0';
    } else {
        out->header_len = len;
    }

    return 0;
}


void print_http_packet(const unsigned char *packet, uint32_t wire_len, const http_packet *p)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);

    if (p->is_response)
        printf("=== HTTP Response ===\n");
    else
        printf("=== HTTP Request ===\n");
    printf("Src MAC        : %s\n", p->tcp.ether.src_mac);
    printf("Dst MAC        : %s\n", p->tcp.ether.dst_mac);
    printf("Ethertype      : 0x%04x\n", ntohs(p->tcp.ether.ethertype));
    puts("\n");
    printf("Source IP      : %s\n", p->tcp.ip.src);
    printf("Destination IP : %s\n", p->tcp.ip.dst);
    puts("\n");
    printf("Source Port     : %u\n", p->tcp.src_port);
    printf("Destination Port: %u\n", p->tcp.dst_port);
    printf("Seq Number      : %u\n", p->tcp.seq_num);
    printf("Ack Number      : %u\n", p->tcp.ack_num);
    printf("Flags           : %s\n", p->tcp.flags_str);
    printf("Window Size     : %u\n", p->tcp.window);
    puts("\n");
    printf("\n[%s] HTTP %s:%d -> %s:%d\n", time_buf,
           p->tcp.ip.src, p->tcp.src_port,
           p->tcp.ip.dst, p->tcp.dst_port);
    printf("Header Length   : %u bytes\n", p->header_len);
    printf("Data Length     : %u bytes\n", p->data_len);
    if (p->is_response)
    {
        printf("Version       : %s\n", p->version);
        printf("Status Code   : %d\n", p->status_code);
        printf("Status Msg    : %s\n", p->status_message);
    }
    else if (p->is_request)
    {
        printf("Method        : %s\n", p->method);
        printf("Path          : %s\n", p->path);
        printf("Version       : %s\n", p->version);
    }

    if (*p->headers)
    {
        printf("\nHeaders:\n%s\n", p->headers);
    }

    if (*p->body)
    {
        printf("\nBody:\n%s\n", p->body);
    }

    printf("Total on wire   : %u bytes\n", wire_len);
    printf("Raw Bytes       : ");
    dump_hex_single_line(packet, wire_len);
    printf("\n===========================\n");
}

void http_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;

    http_packet p;
    int offset = 0;


    offset += parse_ethernet_header(packet, header->len, &p.tcp.ether);
    offset += parse_ip_header(packet + offset, header->len - offset, &p.tcp.ip);
    offset += parse_tcp_header(packet + offset, header->len - offset, &p.tcp);
    
    print_tcp_packet(packet, header->len, &p.tcp);

    uint16_t sport = p.tcp.src_port;
    uint16_t dport = p.tcp.dst_port;

    if (sport != HTTP_PORT && dport != HTTP_PORT && sport != HTTP_PORT_ALT && dport != HTTP_PORT_ALT)
    {
        fprintf(stderr, "Error: can't recongnize HTTP port\n");
        return;
    }

    const unsigned char *payload = packet + offset;
    int payload_len = p.tcp.data_len;
    if (payload_len > 0) {
        parse_http_packet(payload, header->len - offset, &p);
        print_http_packet(packet, header->len, &p);
    }
}