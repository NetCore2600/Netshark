#include "handler.h"
#include "netshark.h"
#include "parser.h"

void http_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
    
    struct ether_header *eth;
    struct iphdr *ip;
    tcp_header *tcp;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    time_t now;
    struct tm *timeinfo;
    char time_str[20];
    int ip_header_len;
    int tcp_header_len;
    int payload_len;
    const unsigned char *payload;

    // Récupération de l'heure actuelle
    time(&now);
    timeinfo = localtime(&now);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);

    // Analyse de l'en-tête Ethernet
    eth = (struct ether_header *)packet;
    
    // Vérification que c'est bien un paquet IP
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // Analyse de l'en-tête IP
    ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    ip_header_len = (ip->ihl) * 4;

    // Vérification que c'est bien un paquet TCP
    if (ip->protocol != IPPROTO_TCP) {
        return;
    }

    // Analyse de l'en-tête TCP
    tcp = (tcp_header *)(packet + sizeof(struct ether_header) + ip_header_len);
    tcp_header_len = ((tcp->th_offx2 & 0xf0) >> 4) * 4;

    // Vérification que c'est bien un paquet HTTP (port 80 ou 8080)
    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);
    if (src_port != 80 && src_port != 8080 && dst_port != 80 && dst_port != 8080) {
        return;
    }

    // Extraction des données
    payload = (unsigned char *)(packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len);
    payload_len = header->len - (sizeof(struct ether_header) + ip_header_len + tcp_header_len);

    // Conversion des adresses IP
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

    // Traitement des données HTTP
    if (payload_len > 0) {
        char *data = (char *)payload;
        char *end = data + payload_len;
        char *line_end;
        char method[10] = {0};
        char path[256] = {0};
        char version[10] = {0};
        int status_code = 0;
        char status_message[256] = {0};

        // Affichage des informations de base
        printf("\n[%s] HTTP %s:%d -> %s:%d\n", 
               time_str, src_ip, src_port, dst_ip, dst_port);

        // Vérifier si c'est une requête ou une réponse HTTP
        if (strncmp(data, "HTTP/", 5) == 0) {
            // C'est une réponse HTTP
            sscanf(data, "%s %d %[^\r\n]", version, &status_code, status_message);
            printf("=== HTTP Response ===\n");
            printf("Version: %s\n", version);
            printf("Status Code: %d\n", status_code);
            printf("Status Message: %s\n", status_message);
        } else {
            // C'est une requête HTTP
            sscanf(data, "%s %s %s", method, path, version);
            printf("=== HTTP Request ===\n");
            printf("Method: %s\n", method);
            printf("Path: %s\n", path);
            printf("Version: %s\n", version);
        }

        // Analyser les en-têtes
        printf("\nHeaders:\n");
        char *current = strstr(data, "\r\n");
        if (current) {
            current += 2; // Passer les \r\n
            while (current < end) {
                line_end = strstr(current, "\r\n");
                if (!line_end) break;
                
                if (line_end == current) {
                    // Fin des en-têtes
                    break;
                }

                // Afficher l'en-tête
                printf("%.*s\n", (int)(line_end - current), current);
                current = line_end + 2;
            }
        }

        // Afficher le corps si présent
        if (current && current < end) {
            printf("\nBody:\n");
            printf("%.*s\n", (int)(end - current), current);
        }

        printf("==========================\n");
    }
}