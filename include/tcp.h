#ifndef TCP_H
#define TCP_H

#include "netshark.h"
#include "ethernet.h"
#include "ip.h"

/*** MACROS ***/
// TCP Flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20    

/*** STRUCTURE DEFINITIONS ***/
typedef struct _tcp_header {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offx2;
    uint8_t  flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
} tcp_header;

// Parsed TCP Packet Struct
typedef struct {
    eth_header ether;               // Ethernet header
    ip_header ip;                   // IP header (raw)
    uint16_t src_port;              // TCP source port
    uint16_t dst_port;              // TCP dest port
    uint32_t seq_num;               // Sequence number
    uint32_t ack_num;               // Acknowledgment number
    uint8_t  header_len;            // Header length (bytes)
    uint8_t  flags;                 // TCP flags
    uint16_t window;                // Window size
    uint16_t checksum;              // TCP checksum
    uint16_t urg_ptr;               // Urgent pointer
    uint16_t data_len;              // TCP payload length
    char flags_str[32];             // TCP flag string
} tcp_packet;

/*** PROTOTYPES ***/
void tcp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_tcp_header(const unsigned char *frame, size_t frame_len, tcp_packet *out);
void get_tcp_flags(unsigned char flags, char *str);
void print_tcp_packet(const unsigned char *packet, uint32_t wire_len, const tcp_packet *p);

#endif /* TCP_H */
