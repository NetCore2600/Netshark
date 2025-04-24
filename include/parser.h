#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include "netcore.h"




/***********************************|
|              MACRO                |
|__________________________________*/

// Définitions des flags TCP
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20





/***********************************|
|            STRUCTURE              |
|__________________________________*/




/***********************************|
|            PROTOTYPE              |
|__________________________________*/

void parse_tcp_packet(const unsigned char *packet, int packet_len);

#endif /* TCP_PARSER_H */