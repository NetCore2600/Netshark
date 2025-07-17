#ifndef TLS_H
#define TLS_H

#include "netshark.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"

/*** MACROS ***/
// TLS Record Types
#define TLS_TYPE_CHANGE_CIPHER_SPEC 20
#define TLS_TYPE_ALERT             21
#define TLS_TYPE_HANDSHAKE         22
#define TLS_TYPE_APPLICATION_DATA  23

// TLS Handshake Types
#define TLS_HANDSHAKE_HELLO_REQUEST       0
#define TLS_HANDSHAKE_CLIENT_HELLO        1
#define TLS_HANDSHAKE_SERVER_HELLO        2
#define TLS_HANDSHAKE_CERTIFICATE         11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST 13
#define TLS_HANDSHAKE_SERVER_HELLO_DONE   14
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY  15
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_FINISHED            20

// TLS Versions
#define TLS_VERSION_1_0  0x0301
#define TLS_VERSION_1_1  0x0302
#define TLS_VERSION_1_2  0x0303
#define TLS_VERSION_1_3  0x0304
#define SSL_VERSION_3_0  0x0300

// Common TLS ports
#define TLS_PORT_HTTPS   443
#define TLS_PORT_SMTPS   465
#define TLS_PORT_IMAPS   993
#define TLS_PORT_POP3S   995

/*** STRUCTURE DEFINITIONS ***/
typedef struct _tls_record_header {
    uint8_t  type;
    uint16_t version;
    uint16_t length;
} tls_record_header;

typedef struct _tls_handshake_header {
    uint8_t  type;
    uint8_t  length[3];  // 24-bit length field
} tls_handshake_header;

typedef struct _tls_client_hello {
    uint16_t version;
    uint8_t  random[32];
    uint8_t  session_id_len;
    // Variable length fields follow
} tls_client_hello;

typedef struct _tls_server_hello {
    uint16_t version;
    uint8_t  random[32];
    uint8_t  session_id_len;
    // Variable length fields follow
} tls_server_hello;

// Parsed TLS Packet Structure
typedef struct {
    tcp_packet tcp;                 // TCP packet info
    
    // TLS Record Layer
    uint8_t  record_type;           // TLS record type
    uint16_t tls_version;           // TLS version
    uint16_t record_length;         // Record length
    
    // TLS Handshake (if applicable)
    uint8_t  handshake_type;        // Handshake message type
    uint32_t handshake_length;      // Handshake message length
    uint16_t handshake_version;     // Version in handshake
    
    // Parsed string representations
    char record_type_str[32];       // Record type string
    char handshake_type_str[32];    // Handshake type string
    char version_str[16];           // Version string
    char server_name[256];          // SNI server name (if present)
    
    // For ECDHE key exchange
    uint8_t pubkey_len;
    unsigned char pubkey[256];  // adjust as needed
    uint16_t named_curve;
    uint8_t has_pubkey;

    // Flags
    uint8_t is_encrypted;           // Is payload encrypted
    uint8_t has_sni;                // Has Server Name Indication
    uint8_t is_handshake;           // Is handshake message
    
    uint16_t payload_len;           // TLS payload length
} tls_packet;

/*** PROTOTYPES ***/
void tls_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_tls_record(const unsigned char *data, size_t data_len, tls_packet *out);
int parse_tls_handshake(const unsigned char *data, size_t data_len, tls_packet *out);
int parse_client_hello(const unsigned char *data, size_t data_len, tls_packet *out);
int parse_server_hello(const unsigned char *data, size_t data_len, tls_packet *out);
int extract_sni(const unsigned char *data, size_t data_len, char *sni_out, size_t sni_max);
void get_tls_record_type_str(uint8_t type, char *str);
void get_tls_handshake_type_str(uint8_t type, char *str);
void get_tls_version_str(uint16_t version, char *str);
int is_tls_port(uint16_t port);
int is_likely_tls(const unsigned char *data, size_t len);
void print_tls_packet(const unsigned char *packet, uint32_t wire_len, const tls_packet *p);

#endif /* TLS_H */