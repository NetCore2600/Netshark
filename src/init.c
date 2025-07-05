#include "netshark.h"
#include "handler.h"


static HandlerPacket handlers = {
    .tcp = tcp_handler,
    .udp = udp_handler,
    .arp = arp_handler,
    .ftp = ftp_handler,
    .http = http_handler
};

static void init_inet(NetShark *n, Args args) {
    // Get the list of devices
    if (pcap_findalldevs(&n->alldevs, n->errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", n->errbuf);
        exit(1);
    }

    // Verify if the specified interface exists
    pcap_if_t *interface;
    int found = 0;
    for (interface = n->alldevs; interface != NULL; interface = interface->next) {
        if (strcmp(interface->name, args.dev) == 0) {
            found = 1;
            n->selected_dev = interface;  // Mémoriser l'interface sélectionnée
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "Interface %s not found\n", args.dev);
        pcap_freealldevs(n->alldevs);
        exit(1);
    }
}

/*
 * The pcap_open_live function in C++ is used to open a network device for live packet capture. 
 * It takes parameters for the device name, the maximum number of bytes to capture per packet, 
 * a flag to enable promiscuous mode, a read timeout in milliseconds, and a pointer to a 
 * buffer for error messages, returning a pointer to a pcap_t structure for subsequent packet 
 * capture operations.
 * 
 * see: https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
 * 
 */
static void init_pcap_handle(NetShark *n) {
    // Open the session in promiscuous mode
    n->handle = pcap_open_live(n->selected_dev->name, BUFSIZ, 1, 1000, n->errbuf);
    if (n->handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", n->selected_dev->name, n->errbuf);
        pcap_freealldevs(n->alldevs);
        exit(2);
    }
}

static void init_datalink(NetShark *n) {
    // Get the data link type
    int datalink = pcap_datalink(n->handle);
    switch (datalink) {
        case DLT_EN10MB:
            printf("Data link type: Ethernet\n");
            break;
        case DLT_NULL:
            printf("Data link type: NULL\n");
            break;
        default:
            printf("Unknown data link type: %d\n", datalink);
            pcap_close(n->handle);
            pcap_freealldevs(n->alldevs);
            exit(3);
    }
}

static void init_filter(NetShark *n, Args args) {
    char *filter_exp = args.filter_exp;
    char bpf_filter[256] = {0};
    
    // Traduction logique vers filtre BPF
    if (strcmp(args.filter_exp, "http") == 0) {
        filter_exp = "tcp port 80";
    } else if (strcmp(args.filter_exp, "ftp") == 0) {
        filter_exp = "tcp port 21";
    } else if (strcmp(args.filter_exp, "tcp") == 0) {
        filter_exp = "tcp";
    } else if (strcmp(args.filter_exp, "udp") == 0) {
        filter_exp = "udp";
    } else if (strcmp(args.filter_exp, "arp") == 0) {
        filter_exp = "arp";
    }

    // Copier le filtre traduit
    strncpy(bpf_filter, filter_exp, sizeof(bpf_filter) - 1);

    if (DEBUG_MODE) {
        printf("Filter expression: %s\n", filter_exp);
        printf("Applying BPF filter: %s\n", bpf_filter);
    }

    // Compiler et appliquer le filtre
    if (pcap_compile(n->handle, &n->fp, bpf_filter, 0, n->net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", bpf_filter, pcap_geterr(n->handle));
        pcap_close(n->handle);
        pcap_freealldevs(n->alldevs);
        exit(4);
    }

    if (pcap_setfilter(n->handle, &n->fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", bpf_filter, pcap_geterr(n->handle));
        pcap_freecode(&n->fp);
        pcap_close(n->handle);
        pcap_freealldevs(n->alldevs);
        exit(5);
    }
}

static void init_packet_handler(NetShark *n, Args args) {
    if (!strcmp(args.filter_exp, "tcp")) {
        n->handler = handlers.tcp;
    } else if (!strcmp(args.filter_exp, "udp")) {
        n->handler = handlers.udp;
    } else if (!strcmp(args.filter_exp, "arp")) {
        n->handler = handlers.arp;
    } else if (!strcmp(args.filter_exp, "ftp")) {
        n->handler = handlers.ftp;
    } else if (!strcmp(args.filter_exp, "http")) {
        n->handler = handlers.http;
    } else {
        fprintf(stderr, "Unsupported filter: %s\n", args.filter_exp);
        exit(1);
    }
}

void init(NetShark *n, Args args) {
    n->alldevs = NULL;
    n->handle = NULL;
    n->handler = NULL;
    n->fp.bf_insns = NULL;
    n->fp.bf_len = 0;
    n->net = 0;
    n->selected_dev = NULL;  // Initialiser le pointeur de l'interface sélectionnée

    init_inet(n, args);
    init_pcap_handle(n);
    init_datalink(n);

    // Obtenir l'adresse réseau pour le filtre
    bpf_u_int32 netp;
    if (pcap_lookupnet(n->selected_dev->name, &n->net, &netp, n->errbuf) == -1) {
        fprintf(stderr, "Warning: Couldn't get netmask for device %s: %s\n", 
                n->selected_dev->name, n->errbuf);
        n->net = 0;
    }

    init_packet_handler(n, args);
    init_filter(n, args);
}