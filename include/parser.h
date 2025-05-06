#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include "netshark.h"




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

// Définitions des flags UDP
#define UDP_SOURCE_PORT 0x0001
#define UDP_DEST_PORT  0x0002
#define UDP_LENGTH     0x0004
#define UDP_CHECKSUM   0x0008

// Définitions des types ARP
#define ARP_REQUEST    1
#define ARP_REPLY      2
#define ARP_HARDWARE_TYPE_ETHERNET 1

// Définitions des ports FTP
#define FTP_PORT        21
#define FTP_DATA_PORT   20

// Commandes FTP de base
#define FTP_CMD_USER "USER"
#define FTP_CMD_PASS "PASS"
#define FTP_CMD_ACCT "ACCT"
#define FTP_CMD_CWD  "CWD"
#define FTP_CMD_CDUP "CDUP"
#define FTP_CMD_SMNT "SMNT"
#define FTP_CMD_QUIT "QUIT"
#define FTP_CMD_REIN "REIN"
#define FTP_CMD_PORT "PORT"
#define FTP_CMD_PASV "PASV"
#define FTP_CMD_TYPE "TYPE"
#define FTP_CMD_STRU "STRU"
#define FTP_CMD_MODE "MODE"
#define FTP_CMD_RETR "RETR"
#define FTP_CMD_STOR "STOR"
#define FTP_CMD_STOU "STOU"
#define FTP_CMD_APPE "APPE"
#define FTP_CMD_ALLO "ALLO"
#define FTP_CMD_REST "REST"
#define FTP_CMD_RNFR "RNFR"
#define FTP_CMD_RNTO "RNTO"
#define FTP_CMD_ABOR "ABOR"
#define FTP_CMD_DELE "DELE"
#define FTP_CMD_RMD  "RMD"
#define FTP_CMD_MKD  "MKD"
#define FTP_CMD_PWD  "PWD"
#define FTP_CMD_LIST "LIST"
#define FTP_CMD_NLST "NLST"
#define FTP_CMD_SITE "SITE"
#define FTP_CMD_SYST "SYST"
#define FTP_CMD_STAT "STAT"
#define FTP_CMD_HELP "HELP"
#define FTP_CMD_NOOP "NOOP"



/***********************************|
|            STRUCTURE              |
|__________________________________*/





/***********************************|
|            PROTOTYPE              |
|__________________________________*/

void parse_tcp_packet(const unsigned char *packet, size_t packet_len);
void parse_udp_packet(const unsigned char *packet, size_t packet_len);
void parse_arp_packet(const unsigned char *packet, size_t packet_len);
void parse_ftp_packet(const unsigned char *packet, size_t packet_len);



#endif /* TCP_PARSER_H */