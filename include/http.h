#ifndef HTTP_H
#define HTTP_H

#include "netshark.h"

/*** MACROS ***/
// Methods
#define HTTP_METHOD_GET     "GET"
#define HTTP_METHOD_POST    "POST"
#define HTTP_METHOD_PUT     "PUT"
#define HTTP_METHOD_DELETE  "DELETE"
#define HTTP_METHOD_HEAD    "HEAD"
#define HTTP_METHOD_OPTIONS "OPTIONS"
#define HTTP_METHOD_TRACE   "TRACE"
#define HTTP_METHOD_CONNECT "CONNECT"

// Versions
#define HTTP_VERSION_1_0    "HTTP/1.0"
#define HTTP_VERSION_1_1    "HTTP/1.1"
#define HTTP_VERSION_2_0    "HTTP/2.0"

// Ports
#define HTTP_PORT       80
#define HTTP_PORT_ALT   8080

/*** PROTOTYPES ***/
void http_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void parse_http_packet(const unsigned char *packet, size_t packet_len);

#endif /* HTTP_H */
