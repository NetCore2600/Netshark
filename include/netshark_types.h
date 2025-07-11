#ifndef NETSHARK_TYPES_H
#define NETSHARK_TYPES_H

#include <sys/types.h>
#include <sys/time.h>

// Types de base
typedef unsigned int bpf_u_int32;
typedef unsigned char u_char;

// Constantes
#define NETSHARK_ERRBUF_SIZE 256

// Structures de base
struct netshark_pkthdr {
    struct timeval ts;    /* time stamp */
    bpf_u_int32 caplen;   /* length of portion present */
    bpf_u_int32 len;      /* length of this packet */
};

struct netshark_stat {
    u_int ps_recv;        /* number of packets received */
    u_int ps_drop;        /* number of packets dropped */
    u_int ps_ifdrop;      /* drops by interface */
};

struct netshark_if {
    struct netshark_if *next;
    char *name;           /* name to hand to "netshark_open_live()" */
    char *description;    /* textual description of interface, or NULL */
    struct netshark_addr *addresses;
    bpf_u_int32 flags;    /* NETSHARK_IF_ interface flags */
};

struct netshark_addr {
    struct netshark_addr *next;
    struct sockaddr *addr;        /* address */
    struct sockaddr *netmask;     /* netmask for that address */
    struct sockaddr *broadaddr;   /* broadcast address for that address */
    struct sockaddr *dstaddr;     /* P2P destination address for that address */
};

struct bpf_program {
    u_int bf_len;
    struct bpf_insn *bf_insns;
};

// Structure netshark
struct netshark {
    int activated;
    int linktype;
    char *errbuf;
    // Autres champs nécessaires pour notre implémentation
};

// Types typedef
typedef struct netshark netshark_t;
typedef struct netshark_if netshark_if_t;
typedef struct netshark_addr netshark_addr_t;

// Handler type
typedef void (*netshark_handler)(u_char *, const struct netshark_pkthdr *, const u_char *);

// DLT constants
#define DLT_EN10MB 1
#define DLT_NULL 0

#endif /* NETSHARK_TYPES_H */ 