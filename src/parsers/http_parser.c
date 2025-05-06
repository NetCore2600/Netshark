#include "parser.h"



void parse_http_packet(const unsigned char *packet, size_t packet_len) {
    char *data = (char *)packet;
    char *end = data + packet_len;
    char *line_end;
    char method[10] = {0};
    char path[256] = {0};
    char version[10] = {0};
    int status_code = 0;
    char status_message[256] = {0};

    // Vérifier si c'est une requête ou une réponse HTTP
    if (strncmp(data, "HTTP/", 5) == 0) {
        // C'est une réponse HTTP
        sscanf(data, "%s %d %[^\r\n]", version, &status_code, status_message);
        printf("\n=== HTTP Response ===\n");
        printf("Version: %s\n", version);
        printf("Status Code: %d\n", status_code);
        printf("Status Message: %s\n", status_message);
    } else {
        // C'est une requête HTTP
        sscanf(data, "%s %s %s", method, path, version);
        printf("\n=== HTTP Request ===\n");
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

