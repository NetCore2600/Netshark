### NETCORE 2600
```
███╗   ██╗███████╗████████╗ ██████╗ ██████╗ ██████╗ ███████╗    ██████╗  ██████╗  ██████╗  ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝    ╚════██╗██╔════╝ ██╔═████╗██╔═████╗
██╔██╗ ██║█████╗     ██║   ██║     ██║   ██║██████╔╝█████╗       █████╔╝███████╗ ██║██╔██║██║██╔██║
██║╚██╗██║██╔══╝     ██║   ██║     ██║   ██║██╔══██╗██╔══╝      ██╔═══╝ ██╔═══██╗████╔╝██║████╔╝██║
██║ ╚████║███████╗   ██║   ╚██████╗╚██████╔╝██║  ██║███████╗    ███████╗╚██████╔╝╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ 
```

### 1. En-têtes et Définitions
```c
#include <stdio.h>      // Pour les fonctions d'entrée/sortie
#include <pcap.h>       // Pour la capture de paquets
#include <string.h>     // Pour les fonctions de manipulation de chaînes
#include <stdlib.h>     // Pour les fonctions standard
#include <netinet/in.h> // Pour les structures de réseau
#include <arpa/inet.h>  // Pour les fonctions de conversion d'adresses
#include <time.h>       // Pour les fonctions de temps
#include <net/ethernet.h> // Pour les structures Ethernet
#include <netinet/tcp.h>  // Pour les structures TCP
#include <netinet/ip.h>   // Pour les structures IP

// Définitions des flags TCP
#define TH_FIN  0x01    // Flag FIN (fin de connexion)
#define TH_SYN  0x02    // Flag SYN (synchronisation)
#define TH_RST  0x04    // Flag RST (réinitialisation)
#define TH_PUSH 0x08    // Flag PUSH (pousser les données)
#define TH_ACK  0x10    // Flag ACK (acquittement)
#define TH_URG  0x20    // Flag URG (urgent)
```

### 2. Structures des En-têtes
```c
// Structure de l'en-tête Ethernet
struct eth_header {
    u_char ether_dhost[6];  // Adresse MAC destination
    u_char ether_shost[6];  // Adresse MAC source
    u_short ether_type;     // Type de protocole (ex: IP)
};

// Structure de l'en-tête IP
struct ip_header {
    u_char ip_vhl;         // Version et longueur de l'en-tête
    u_char ip_tos;         // Type de service
    u_short ip_len;        // Longueur totale du paquet
    u_short ip_id;         // Identificateur
    u_short ip_off;        // Fragment offset
    u_char ip_ttl;         // Time to Live
    u_char ip_p;           // Protocole (ex: TCP)
    u_short ip_sum;        // Checksum
    struct in_addr ip_src; // Adresse IP source
    struct in_addr ip_dst; // Adresse IP destination
};

// Structure de l'en-tête TCP
struct tcp_header {
    u_short th_sport;    // Port source
    u_short th_dport;    // Port destination
    u_int th_seq;        // Numéro de séquence
    u_int th_ack;        // Numéro d'acquittement
    u_char th_offx2;     // Longueur de l'en-tête et flags
    u_char th_flags;     // Flags TCP
    u_short th_win;      // Taille de la fenêtre
    u_short th_sum;      // Checksum
    u_short th_urp;      // Pointeur urgent
};
```

### 3. Fonction d'Analyse des Flags TCP
```c
void get_tcp_flags(u_char flags, char *flag_str) {
    flag_str[0] = '\0';  // Initialisation de la chaîne
    if (flags & TH_FIN) strcat(flag_str, "FIN ");  // Fin de connexion
    if (flags & TH_SYN) strcat(flag_str, "SYN ");  // Synchronisation
    if (flags & TH_RST) strcat(flag_str, "RST ");  // Réinitialisation
    if (flags & TH_PUSH) strcat(flag_str, "PSH "); // Pousser les données
    if (flags & TH_ACK) strcat(flag_str, "ACK ");  // Acquittement
    if (flags & TH_URG) strcat(flag_str, "URG ");  // Urgent
}
```

### 4. Gestionnaire de Paquets
```c
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Variables pour stocker les en-têtes et informations
    struct eth_header *eth;
    struct ip_header *ip;
    struct tcp_header *tcp;
    char flag_str[20];
    int size_ip, size_tcp;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    static int packet_count = 0;

    packet_count++;  // Incrémentation du compteur de paquets

    // Analyse de l'en-tête Ethernet
    eth = (struct eth_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    // Analyse de l'en-tête IP
    ip = (struct ip_header *)(packet + sizeof(struct eth_header));
    size_ip = (ip->ip_vhl & 0x0f) * 4;
    if (ip->ip_p != IPPROTO_TCP) return;

    // Analyse de l'en-tête TCP
    tcp = (struct tcp_header *)(packet + sizeof(struct eth_header) + size_ip);
    size_tcp = ((tcp->th_offx2 & 0xf0) >> 4) * 4;

    // Conversion des adresses IP
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Analyse des flags TCP
    get_tcp_flags(tcp->th_flags, flag_str);

    // Affichage des informations du paquet
    printf("%5d %f %s → %s TCP %d %d → %d [%s] Seq=%u Ack=%u Win=%d Len=%d\n",
           packet_count,
           (double)header->ts.tv_sec + (double)header->ts.tv_usec / 1000000.0,
           src_ip, dst_ip,
           ntohs(ip->ip_len),
           ntohs(tcp->th_sport), ntohs(tcp->th_dport),
           flag_str,
           ntohl(tcp->th_seq), ntohl(tcp->th_ack),
           ntohs(tcp->th_win),
           ntohs(ip->ip_len) - size_ip - size_tcp);
}
```

### 5. Fonction d'Aide
```c
void print_usage(char *program_name) {
    printf("Usage: %s -i interface -f \"filter\"\n", program_name);
    printf("Example: %s -i eth0 -f \"tcp\"\n", program_name);
    exit(1);
}
```

### 6. Fonction Principale
```c
int main(int argc, char **argv) {
    // Variables pour la capture
    char *dev = NULL;
    char *filter_exp = NULL;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;

    // Analyse des arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) dev = argv[++i];
            else print_usage(argv[0]);
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) filter_exp = argv[++i];
            else print_usage(argv[0]);
        }
    }

    // Vérification des arguments
    if (dev == NULL || filter_exp == NULL) print_usage(argv[0]);

    // Recherche des interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Vérification de l'interface
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

    // Ouverture de l'interface
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    // Vérification du type de lien
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 3;
    }

    // Compilation et application du filtre
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

    // Démarrage de la capture
    printf("\nStarting packet capture on %s with filter: %s\n", dev, filter_exp);
    while (1) {
        pcap_loop(handle, 10, packet_handler, NULL);
    }

    // Nettoyage
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
```
### Compilation et Utilisation :
```bash
gcc main.c -lpcap -o tshark
./tshark -i eth0 -f "tcp"
```
