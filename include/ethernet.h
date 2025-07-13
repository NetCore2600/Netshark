/* --------------- ethernet.h -------------------------------------------- */
#ifndef ETHERNET_H
# define ETHERNET_H

#include <stdint.h>
#include <stddef.h>

#define ETH_ADDR_STRLEN   18      /* "aa:bb:cc:dd:ee:ff\0"            */
#define ETH_MIN_FRAME     14      /* dest + src + type/len            */
#define ETHERTYPE_VLAN    0x8100  /* IEEE 802.1Q                      */
#define ETHERTYPE_QINQ    0x88A8  /* IEEE 802.1ad (provider tag)      */
#define ETHERTYPE_ARP     0x0806  /* ARP (EtherType)                  */
#define ETHERTYPE_IPV4    0x0800  /* IPv4 (EtherType)                 */
#define ETHERTYPE_IPV6    0x86DD  /* IPv6 (EtherType)                 */
#define ETHERTYPE_IPX     0x8137  /* IPX (EtherType)                  */
#define ETHERTYPE_RARP    0x8035  /* RARP (EtherType)                 */
#define ETHERTYPE_MPLS    0x8847  /* MPLS unicast (EtherType)         */
#define ETHERTYPE_MPLS_MCAST 0x8848  /* MPLS multicast (EtherType)    */

/* ---- raw wire header (no FCS) ---------------------------------------- */
typedef struct _ether_info {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type_len;           /* EtherType (>= 0x0600) or length */
} ether_info;

/* ---- optional 802.1Q tag --------------------------------------------- */
typedef struct _vlan_tag {
    uint16_t tpid;               /* 0x8100 or 0x88A8                 */
    uint16_t tci;                /* PCP(3) | DEI(1) | VID(12)        */
} vlan_tag;

/* ---- human‑readable result ------------------------------------------- */
typedef struct {
    char     dst_mac[ETH_ADDR_STRLEN];
    char     src_mac[ETH_ADDR_STRLEN];

    uint16_t ethertype;          /* host byte order                  */

    /* VLAN (set only if present) */
    int      has_vlan;
    uint16_t vlan_tpid;          /* 0x8100 / 0x88A8                  */
    uint16_t vlan_vid;           /* 0‑4095                           */
    uint8_t  vlan_pcp;           /* 0‑7                              */
} eth_header;

/* ---- prototype ------------------------------------------------------- */
int parse_ethernet_header(const unsigned char *buf, size_t len, eth_header *out);

#endif /* ETHERNET_H */
