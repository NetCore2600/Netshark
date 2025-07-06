#ifndef ARP_H
# define ARP_H

#include "netshark.h"
#include "ethernet.h"

/*** MACROS ***/
#define ARP_REQUEST                 1
#define ARP_REPLY                   2
#define ARP_HARDWARE_TYPE_ETHERNET  1

/*** STRUCTURE ***/
typedef struct _arp_header {
    unsigned short ar_hrd;
    unsigned short ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    unsigned short ar_op;
    unsigned char ar_sha[6];
    unsigned char ar_sip[4];
    unsigned char ar_tha[6];
    unsigned char ar_tip[4];
} arp_header;

typedef struct {
    /* ---- Ethernet header (comes first on wire) -------------------- */
    ether ether;               

    /* ---- ARP header (wire order) ---------------------------------- */
    uint16_t hardware_type;              /* HTYPE  */
    uint16_t protocol_type;              /* PTYPE  */
    uint8_t  hardware_size;              /* HLEN   */
    uint8_t  protocol_size;              /* PLEN   */
    uint16_t operation;                  /* OPER   */

    char     sender_mac[ETH_ADDR_STRLEN];   /* SHA   */
    char     sender_ip[INET_ADDRSTRLEN];    /* SPA   */
    char     target_mac[ETH_ADDR_STRLEN];   /* THA   */
    char     target_ip[INET_ADDRSTRLEN];    /* TPA   */
} arp_packet;

/*** PROTOTYPES ***/
void arp_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
int parse_arp_packet(const unsigned char *frame, size_t frame_len, arp_packet *out);

#endif /* ARP_H */
