#ifndef FTP_H
#define FTP_H

#include "netshark.h"

/*** MACROS ***/
#define FTP_PORT        21
#define FTP_DATA_PORT   20

// FTP Commands
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

/*** STRUCTURE ***/
typedef struct {
    char command[5];
    char *argument;
} ftp_command;

typedef struct {
    int code;
    char *message;
} ftp_response;

struct ftp_data {
    char command[5];
    char argument[256];
    unsigned int code;
    char message[512];
};

/*** PROTOTYPES ***/
void ftp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void parse_ftp_packet(const unsigned char *packet, size_t packet_len);

#endif /* FTP_H */
