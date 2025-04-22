/* Netcore - Tshark
   Jonathan Todnelier
   
   To compile:
   >gcc main.c -lpcap -o tshark

   Usage:
   ./tshark -i interface -f "filter"
   Example:
   ./tshark -i eth0 -f "tcp"
*/

#include "tshark.h"

// Fonction pour obtenir les flags TCP
void get_tcp_flags(unsigned char flags, char *flag_str) {
    flag_str[0] = '\0';
    if (flags & TH_FIN) strcat(flag_str, "FIN ");
    if (flags & TH_SYN) strcat(flag_str, "SYN ");
    if (flags & TH_RST) strcat(flag_str, "RST ");
    if (flags & TH_PUSH) strcat(flag_str, "PSH ");
    if (flags & TH_ACK) strcat(flag_str, "ACK ");
    if (flags & TH_URG) strcat(flag_str, "URG ");
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) 
{
    eth_header *eth;
    ip_header *ip;
    tcp_header *tcp;
    char flag_str[20];
    int size_ip;
    int size_tcp;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    static int packet_count = 0;

    // Incrémenter le compteur de paquets
    packet_count++;

    // Pointeur vers l'en-tête Ethernet
    eth = (eth_header *)packet;

    // Vérifier si c'est un paquet IP
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // Pointeur vers l'en-tête IP
    ip = (ip_header *)(packet + sizeof(eth_header));
    size_ip = (ip->ip_vhl & 0x0f) * 4;

    // Vérifier si c'est un paquet TCP
    if (ip->ip_p != IPPROTO_TCP) {
        return;
    }

    // Pointeur vers l'en-tête TCP
    tcp = (tcp_header *)(packet + sizeof(eth_header) + size_ip);
    size_tcp = ((tcp->th_offx2 & 0xf0) >> 4) * 4;

    // Convertir les adresses IP en chaînes
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Obtenir les flags TCP
    get_tcp_flags(tcp->th_flags, flag_str);

    // Afficher les informations du paquet
    printf("%5d %f %s → %s TCP %d %d → %d [%s] Seq=%u Ack=%u Win=%d Len=%d\n",
           packet_count,
           (double)header->ts.tv_sec + (double)header->ts.tv_usec / 1000000.0,
           src_ip,
           dst_ip,
           ntohs(ip->ip_len),
           ntohs(tcp->th_sport),
           ntohs(tcp->th_dport),
           flag_str,
           ntohl(tcp->th_seq),
           ntohl(tcp->th_ack),
           ntohs(tcp->th_win),
           ntohs(ip->ip_len) - size_ip - size_tcp);
}

void print_usage(char *program_name) {
    printf("Usage: %s -i interface -f \"filter\"\n", program_name);
    printf("Example: %s -i eth0 -f \"tcp\"\n", program_name);
    exit(1);
}

int main(int argc, char **argv) {
    char *dev = NULL;
    char *filter_exp = NULL;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                dev = argv[++i];
            } else {
                print_usage(argv[0]);
            }
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) {
                filter_exp = argv[++i];
            } else {
                print_usage(argv[0]);
            }
        }
    }

    if (dev == NULL || filter_exp == NULL) {
        print_usage(argv[0]);
    }

    // Get the list of devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Verify if the specified interface exists
    pcap_if_t *d;
    int found = 0;
    for (d = alldevs; d != NULL; d = d->next) {
        if (strcmp(d->name, dev) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "Interface %s not found\n", dev);
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("Using device: %s\n", dev);

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    // Check the link layer type
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 3;
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 4;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 5;
    }

    printf("\nStarting packet capture on %s with filter: %s\n", dev, filter_exp);

    while (1) {
        pcap_loop(handle, 10, packet_handler, NULL);
    }

    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
