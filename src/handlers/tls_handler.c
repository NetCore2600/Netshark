#include "tls.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

void get_tls_record_type_str(uint8_t type, char *str) {
    switch (type) {
        case TLS_TYPE_CHANGE_CIPHER_SPEC:
            strcpy(str, "Change Cipher Spec");
            break;
        case TLS_TYPE_ALERT:
            strcpy(str, "Alert");
            break;
        case TLS_TYPE_HANDSHAKE:
            strcpy(str, "Handshake");
            break;
        case TLS_TYPE_APPLICATION_DATA:
            strcpy(str, "Application Data");
            break;
        default:
            snprintf(str, 32, "Unknown (%u)", type);
            break;
    }
}

void get_tls_handshake_type_str(uint8_t type, char *str) {
    switch (type) {
        case TLS_HANDSHAKE_HELLO_REQUEST:
            strcpy(str, "Hello Request");
            break;
        case TLS_HANDSHAKE_CLIENT_HELLO:
            strcpy(str, "Client Hello");
            break;
        case TLS_HANDSHAKE_SERVER_HELLO:
            strcpy(str, "Server Hello");
            break;
        case TLS_HANDSHAKE_CERTIFICATE:
            strcpy(str, "Certificate");
            break;
        case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
            strcpy(str, "Server Key Exchange");
            break;
        case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
            strcpy(str, "Certificate Request");
            break;
        case TLS_HANDSHAKE_SERVER_HELLO_DONE:
            strcpy(str, "Server Hello Done");
            break;
        case TLS_HANDSHAKE_CERTIFICATE_VERIFY:
            strcpy(str, "Certificate Verify");
            break;
        case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
            strcpy(str, "Client Key Exchange");
            break;
        case TLS_HANDSHAKE_FINISHED:
            strcpy(str, "Finished");
            break;
        default:
            snprintf(str, 32, "Unknown (%u)", type);
            break;
    }
}

void get_tls_version_str(uint16_t version, char *str) {
    switch (version) {
        case SSL_VERSION_3_0:
            strcpy(str, "SSL 3.0");
            break;
        case TLS_VERSION_1_0:
            strcpy(str, "TLS 1.0");
            break;
        case TLS_VERSION_1_1:
            strcpy(str, "TLS 1.1");
            break;
        case TLS_VERSION_1_2:
            strcpy(str, "TLS 1.2");
            break;
        case TLS_VERSION_1_3:
            strcpy(str, "TLS 1.3");
            break;
        default:
            snprintf(str, 16, "Unknown 0x%04x", version);
            break;
    }
}

int is_tls_port(uint16_t port) {
    return (port == TLS_PORT_HTTPS || port == TLS_PORT_SMTPS || 
            port == TLS_PORT_IMAPS || port == TLS_PORT_POP3S);
}

int is_likely_tls(const unsigned char *data, size_t len) {
    if (len < 5) return 0;
    
    uint8_t type = data[0];
    uint16_t version = ntohs(*(uint16_t *)(data + 1));
    
    // Check for valid TLS record type
    if (type < TLS_TYPE_CHANGE_CIPHER_SPEC || type > TLS_TYPE_APPLICATION_DATA)
        return 0;
    
    // Check for reasonable TLS version
    if (version < SSL_VERSION_3_0 || version > TLS_VERSION_1_3)
        return 0;
    
    return 1;
}

int extract_sni(const unsigned char *data, size_t data_len, char *sni_out, size_t sni_max) {
    if (data_len < 43) return 0;  // Minimum ClientHello size
    
    // Skip version (2) + random (32) + session_id_len (1)
    size_t pos = 35;
    
    // Skip session ID
    if (pos >= data_len) return 0;
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;
    
    // Skip cipher suites
    if (pos + 2 > data_len) return 0;
    uint16_t cipher_suites_len = ntohs(*(uint16_t *)(data + pos));
    pos += 2 + cipher_suites_len;
    
    // Skip compression methods
    if (pos >= data_len) return 0;
    uint8_t compression_len = data[pos++];
    pos += compression_len;
    
    // Extensions length
    if (pos + 2 > data_len) return 0;
    uint16_t extensions_len = ntohs(*(uint16_t *)(data + pos));
    pos += 2;
    
    // Parse extensions
    size_t extensions_end = pos + extensions_len;
    while (pos + 4 <= extensions_end && pos + 4 <= data_len) {
        uint16_t ext_type = ntohs(*(uint16_t *)(data + pos));
        uint16_t ext_len = ntohs(*(uint16_t *)(data + pos + 2));
        pos += 4;
        
        if (pos + ext_len > data_len) break;
        
        // Server Name Indication extension (type 0)
        if (ext_type == 0 && ext_len > 5) {
            size_t sni_pos = pos + 2;  // Skip list length
            if (sni_pos + 3 <= pos + ext_len && sni_pos + 3 <= data_len) {
                uint8_t name_type = data[sni_pos];
                uint16_t name_len = ntohs(*(uint16_t *)(data + sni_pos + 1));
                sni_pos += 3;
                
                if (name_type == 0 && name_len > 0 && 
                    sni_pos + name_len <= pos + ext_len && 
                    sni_pos + name_len <= data_len) {
                    
                    size_t copy_len = (name_len < sni_max - 1) ? name_len : sni_max - 1;
                    memcpy(sni_out, data + sni_pos, copy_len);
                    sni_out[copy_len] = '\0';
                    return 1;
                }
            }
        }
        
        pos += ext_len;
    }
    
    return 0;
}

int parse_client_hello(const unsigned char *data, size_t data_len, tls_packet *out) {
    if (data_len < sizeof(tls_client_hello)) return -1;
    
    const tls_client_hello *hello = (const tls_client_hello *)data;
    out->handshake_version = ntohs(hello->version);
    
    // Try to extract SNI
    out->has_sni = extract_sni(data, data_len, out->server_name, sizeof(out->server_name));
    
    return 0;
}

int parse_server_hello(const unsigned char *data, size_t data_len, tls_packet *out) {
    if (data_len < sizeof(tls_server_hello)) return -1;
    
    const tls_server_hello *hello = (const tls_server_hello *)data;
    out->handshake_version = ntohs(hello->version);
    
    return 0;
}

void parse_client_key_exchange(const unsigned char *data, size_t len, tls_packet *out) {
    if (len < 1) return;

    uint8_t pubkey_len = data[0];
    if ((unsigned int)len < (unsigned int) (1 + pubkey_len)) return;

    out->has_pubkey = 1;
    out->pubkey_len = pubkey_len;
    out->named_curve = 0;  // client doesn’t send curve ID
    memcpy(out->pubkey, data + 1, pubkey_len);
}

void parse_server_key_exchange(const unsigned char *data, size_t len, tls_packet *out) {
    if (len < 4) return;

    // uint8_t curve_type = data[0];
    uint16_t named_curve = (data[1] << 8) | data[2];
    uint8_t pubkey_len = data[3];

    if ((unsigned int)len < (unsigned int) (4 + pubkey_len)) return;

    out->has_pubkey = 1;
    out->named_curve = named_curve;
    out->pubkey_len = pubkey_len;
    memcpy(out->pubkey, data + 4, pubkey_len);
}



int parse_tls_handshake(const unsigned char *data, size_t data_len, tls_packet *out) {
    if (data_len < sizeof(tls_handshake_header)) return -1;

    const tls_handshake_header *hs = (const tls_handshake_header *)data;
    out->handshake_type = hs->type;
    out->handshake_length = (hs->length[0] << 16) | (hs->length[1] << 8) | hs->length[2];
    out->is_handshake = 1;

    get_tls_handshake_type_str(out->handshake_type, out->handshake_type_str);

    const unsigned char *handshake_data = data + sizeof(tls_handshake_header);
    size_t handshake_data_len = data_len - sizeof(tls_handshake_header);

    switch (out->handshake_type) {
        case TLS_HANDSHAKE_CLIENT_HELLO:
            parse_client_hello(handshake_data, handshake_data_len, out);
            break;
        case TLS_HANDSHAKE_SERVER_HELLO:
            parse_server_hello(handshake_data, handshake_data_len, out);
            break;
        case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
            parse_server_key_exchange(handshake_data, handshake_data_len, out);
            break;
        case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
            parse_client_key_exchange(handshake_data, handshake_data_len, out);
            break;
        default:
            break;
    }

    return 0;
}



int parse_tls_record(const unsigned char *data, size_t data_len, tls_packet *out) {
    if (!data || !out || data_len < sizeof(tls_record_header))
        return -1;
    
    const tls_record_header *rec = (const tls_record_header *)data;
    out->record_type = rec->type;
    out->tls_version = ntohs(rec->version);
    out->record_length = ntohs(rec->length);
    out->payload_len = out->record_length;
    
    // Check if this looks like encrypted data
    out->is_encrypted = (out->record_type == TLS_TYPE_APPLICATION_DATA);
    
    get_tls_record_type_str(out->record_type, out->record_type_str);
    get_tls_version_str(out->tls_version, out->version_str);
    
    if (out->record_type == TLS_TYPE_HANDSHAKE && 
        data_len > sizeof(tls_record_header)) {
        const unsigned char *handshake_data = data + sizeof(tls_record_header);
        size_t handshake_len = data_len - sizeof(tls_record_header);
        parse_tls_handshake(handshake_data, handshake_len, out);
    } else if (out->record_type == TLS_TYPE_CHANGE_CIPHER_SPEC) {
        // Minimal ChangeCipherSpec message has a payload of 0x01
        out->is_handshake = 1;
        out->handshake_type = TLS_TYPE_CHANGE_CIPHER_SPEC;
        strcpy(out->handshake_type_str, "Change Cipher Spec");
    }


    return sizeof(tls_record_header);
}

void print_tls_packet(const unsigned char *frame, uint32_t wire_len, const tls_packet *p) {
    puts("\n=== TLS Packet ============");
    
    // Ethernet Layer
    printf("Src MAC         : %s\n", p->tcp.ether.src_mac);
    printf("Dst MAC         : %s\n", p->tcp.ether.dst_mac);
    printf("Ethertype       : 0x%04x\n", p->tcp.ether.ethertype);
    puts("");
    
    // IP Layer
    printf("Src IP          : %s\n", p->tcp.ip.src);
    printf("Dst IP          : %s\n", p->tcp.ip.dst);
    printf("IP Version      : %u\n", p->tcp.ip.version);
    printf("IP Header Len   : %u bytes\n", p->tcp.ip.header_len);
    printf("IP Total Len    : %u bytes\n", p->tcp.ip.total_len);
    printf("IP ID           : %u\n", p->tcp.ip.id);
    // printf("IP Flags        : 0x%02x\n", p->tcp.ip.flags);
    printf("IP Frag Offset  : %u\n", p->tcp.ip.frag_off);
    printf("IP TTL          : %u\n", p->tcp.ip.ttl);
    printf("IP Protocol     : %u\n", p->tcp.ip.protocol);
    printf("IP Checksum     : 0x%04x\n", p->tcp.ip.checksum);
    puts("");
    
    // TCP Layer
    printf("Src Port        : %u\n", p->tcp.src_port);
    printf("Dst Port        : %u\n", p->tcp.dst_port);
    printf("TCP Seq Number  : %u\n", p->tcp.seq_num);
    printf("TCP Ack Number  : %u\n", p->tcp.ack_num);
    printf("TCP Header Len  : %u bytes\n", p->tcp.header_len);
    printf("TCP Flags       : 0x%02x (%s)\n", p->tcp.flags, p->tcp.flags_str);
    printf("TCP Window      : %u\n", p->tcp.window);
    printf("TCP Checksum    : 0x%04x\n", p->tcp.checksum);
    printf("TCP Urgent Ptr  : %u\n", p->tcp.urg_ptr);
    printf("TCP Data Len    : %u bytes\n", p->tcp.data_len);
    puts("");
    
    // TLS Record Layer
    printf("TLS Record Type : %u (%s)\n", p->record_type, p->record_type_str);
    printf("TLS Version     : 0x%04x (%s)\n", p->tls_version, p->version_str);
    printf("Record Length   : %u bytes\n", p->record_length);
    printf("Payload Length  : %u bytes\n", p->payload_len);
    printf("Is Encrypted    : %s\n", p->is_encrypted ? "Yes" : "No");
    printf("Is Handshake    : %s\n", p->is_handshake ? "Yes" : "No");
    puts("");
    
    // TLS Handshake Layer (if applicable)
    if (p->is_handshake) {
        if (p->handshake_type != TLS_TYPE_CHANGE_CIPHER_SPEC) {
            printf("Handshake Length: %u bytes\n", p->handshake_length);
        }

        if (p->handshake_version > 0) {
            char hs_version[16];
            get_tls_version_str(p->handshake_version, hs_version);
            printf("Handshake Ver   : 0x%04x (%s)\n", p->handshake_version, hs_version);
        }
        
        printf("Has SNI         : %s\n", p->has_sni ? "Yes" : "No");
        if (p->has_sni) {
            printf("Server Name     : %s\n", p->server_name);
        }
        puts("");
    }

    if (p->has_pubkey) {
        printf("Key Exchange    : Ephemeral Public Key\n");
        if (p->named_curve)
            printf("Curve           : 0x%04x\n", p->named_curve);
        printf("Public Key Len  : %u bytes\n", p->pubkey_len);
        printf("Public Key      : ");
        for (int i = 0; i < p->pubkey_len; ++i) {
            printf("%02x", p->pubkey[i]);
        }
        puts("\n");
    }

    
    // Summary
    printf("Total on wire   : %u bytes\n", wire_len);
    printf("Raw Bytes       : "); dump_hex_single_line(frame, wire_len);
    puts("\n===========================\n");
}


void tls_handler(
    unsigned char            *user,
    const struct pcap_pkthdr *hdr,
    const unsigned char      *frame
) {
    (void)user;
    tls_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    int offset = 0;
    
    // Parse Ethernet header
    int eth_len = parse_ethernet_header(frame + offset, hdr->len - offset, &pkt.tcp.ether);
    if (eth_len < 0) return;
    offset += eth_len;
    
    // Parse IP header
    int ip_len = parse_ip_header(frame + offset, hdr->len - offset, &pkt.tcp.ip);
    if (ip_len < 0) return;
    offset += ip_len;
    
    // Parse TCP header
    int tcp_len = parse_tcp_header(frame + offset, hdr->len - offset, &pkt.tcp);
    if (tcp_len < 0) return;
    offset += tcp_len;
    
    // Check if this might be TLS traffic
    if (pkt.tcp.data_len == 0) return;  // No TCP payload
    
    const unsigned char *tls_data = frame + offset;
    size_t tls_len = hdr->len - offset;
    
    // Basic heuristic: check if it's on a TLS port or looks like TLS
    if (!is_tls_port(pkt.tcp.src_port) && !is_tls_port(pkt.tcp.dst_port)) {
        if (!is_likely_tls(tls_data, tls_len)) {
            return;  // Doesn't look like TLS
        }
    }
    
    // Parse TLS record
    if (parse_tls_record(tls_data, tls_len, &pkt) < 0) {
        return;
    }
    
    print_tls_packet(frame, hdr->len, &pkt);
}