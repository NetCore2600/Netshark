#ifndef HTTP_H
#define HTTP_H

#include "tcp.h"

/*** MACROS ***/
#define HTTP_METHOD_GET     "GET"
#define HTTP_METHOD_POST    "POST"
#define HTTP_METHOD_PUT     "PUT"
#define HTTP_METHOD_DELETE  "DELETE"
#define HTTP_METHOD_HEAD    "HEAD"
#define HTTP_METHOD_OPTIONS "OPTIONS"
#define HTTP_METHOD_TRACE   "TRACE"
#define HTTP_METHOD_CONNECT "CONNECT"

#define HTTP_VERSION_1_0    "HTTP/1.0"
#define HTTP_VERSION_1_1    "HTTP/1.1"
#define HTTP_VERSION_2_0    "HTTP/2.0"

#define HTTP_PORT       80
#define HTTP_PORT_ALT   8080

/*** STRUCTURE DEFINITIONS ***/
typedef struct {
    tcp_packet tcp;

    int is_request;
    int is_response;
    char method[16];
    char path[256];
    char version[16];
    int status_code;
    char status_message[256];
    char headers[1024];
    char body[2048];

    // New fields for HTTP length tracking
    uint16_t header_len;  // Length of HTTP headers
    uint16_t data_len;    // Length of HTTP body
} http_packet;

/*** PROTOTYPES ***/
void http_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_http_packet(const unsigned char *packet, size_t len, http_packet *out);
void print_http_packet(const unsigned char *packet, uint32_t wire_len, const http_packet *p);

#endif /* HTTP_H */
