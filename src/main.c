#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#define BUFFER_SIZE 65536

volatile sig_atomic_t running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\nArrêt de la capture...\n");
}

void print_usage(const char *prog) {
    printf("Usage: %s -i interface [-f protocole]\n", prog);
    printf("Exemple: %s -i eth0 -f tcp\n", prog);
    printf("Protocole: tcp, udp, http, all (défaut: all)\n");
}

void parse_args(int argc, char **argv, char **interface, char **filter) {
    *interface = NULL;
    *filter = "all";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
            *interface = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) {
            *filter = argv[++i];
        }
    }
    if (!*interface) {
        print_usage(argv[0]);
        exit(1);
    }
}

void print_packet(const unsigned char *buffer, int size) {
    if (size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) return;
    const struct ethhdr *eth = (const struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP) return; // On ne traite que IPv4
    const struct iphdr *iph = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
    printf("IP %s -> %s ", src, dst);
    if (iph->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*4);
        int src_port = ntohs(tcp->source);
        int dst_port = ntohs(tcp->dest);
        printf("TCP %d -> %d", src_port, dst_port);
        
        // Détecter HTTP/HTTPS
        if (src_port == 80 || dst_port == 80) {
            printf(" [HTTP]");
        } else if (src_port == 443 || dst_port == 443) {
            printf(" [HTTPS]");
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*4);
        printf("UDP %d -> %d", ntohs(udp->source), ntohs(udp->dest));
    } else {
        printf("PROTO %d", iph->protocol);
    }
    printf(" (Taille: %d)\n", size);
}

int main(int argc, char **argv) {
    char *interface, *filter;
    int sockfd;
    unsigned char buffer[BUFFER_SIZE];

    parse_args(argc, argv, &interface, &filter);
    signal(SIGINT, signal_handler);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        fprintf(stderr, "Erreur lors de la création du socket. Lancez en root.\n");
        return 1;
    }
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(interface);
    if (sll.sll_ifindex == 0) {
        fprintf(stderr, "Interface %s introuvable\n", interface);
        close(sockfd);
        return 1;
    }
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }
    printf("Netshark - Capture sur %s | Filtre: %s\n", interface, filter);
    printf("Ctrl+C pour arrêter\n\n");

    while (running) {
        int size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (size < 0) {
            perror("recvfrom");
            break;
        }
        if (size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) continue;
        const struct ethhdr *eth = (const struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;
        const struct iphdr *iph = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
        
        // Filtrage par protocole
        if (strcmp(filter, "tcp") == 0 && iph->protocol == IPPROTO_TCP) {
            print_packet(buffer, size);
        } else if (strcmp(filter, "udp") == 0 && iph->protocol == IPPROTO_UDP) {
            print_packet(buffer, size);
        } else if (strcmp(filter, "http") == 0 && iph->protocol == IPPROTO_TCP) {
            const struct tcphdr *tcp = (const struct tcphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*4);
            int src_port = ntohs(tcp->source);
            int dst_port = ntohs(tcp->dest);
            if (src_port == 80 || dst_port == 80 || src_port == 443 || dst_port == 443) {
                print_packet(buffer, size);
            }
        } else if (strcmp(filter, "all") == 0) {
            print_packet(buffer, size);
        }
    }
    close(sockfd);
    printf("Capture terminée.\n");
    return 0;
}
