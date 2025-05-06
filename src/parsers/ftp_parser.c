#include "parser.h"

void parse_ftp_packet(const unsigned char *packet, size_t packet_len) {
    char *data = (char *)packet;
    char *end = data + packet_len;
    
    // Recherche des commandes FTP courantes
    if (strncmp(data, FTP_CMD_USER, strlen(FTP_CMD_USER)) == 0) {
        printf("FTP: Tentative de connexion - Utilisateur: %.*s\n", 
               (int)(end - (data + strlen(FTP_CMD_USER) + 1)), 
               data + strlen(FTP_CMD_USER) + 1);
    }
    else if (strncmp(data, FTP_CMD_PASS, strlen(FTP_CMD_PASS)) == 0) {
        printf("FTP: Tentative d'authentification - Mot de passe: *****\n");
    }
    else if (strncmp(data, FTP_CMD_LIST, strlen(FTP_CMD_LIST)) == 0) {
        printf("FTP: Commande LIST\n");
    }
    else if (strncmp(data, FTP_CMD_RETR, strlen(FTP_CMD_RETR)) == 0) {
        printf("FTP: Téléchargement de fichier: %.*s\n", 
               (int)(end - (data + strlen(FTP_CMD_RETR) + 1)), 
               data + strlen(FTP_CMD_RETR) + 1);
    }
    else if (strncmp(data, FTP_CMD_STOR, strlen(FTP_CMD_STOR)) == 0) {
        printf("FTP: Upload de fichier: %.*s\n", 
               (int)(end - (data + strlen(FTP_CMD_STOR) + 1)), 
               data + strlen(FTP_CMD_STOR) + 1);
    }
    else if (strncmp(data, FTP_CMD_CWD, strlen(FTP_CMD_CWD)) == 0) {
        printf("FTP: Changement de répertoire: %.*s\n", 
               (int)(end - (data + strlen(FTP_CMD_CWD) + 1)), 
               data + strlen(FTP_CMD_CWD) + 1);
    }
    else if (strncmp(data, FTP_CMD_MKD, strlen(FTP_CMD_MKD)) == 0) {
        printf("FTP: Création de répertoire: %.*s\n", 
               (int)(end - (data + strlen(FTP_CMD_MKD) + 1)), 
               data + strlen(FTP_CMD_MKD) + 1);
    }
    else if (strncmp(data, FTP_CMD_RMD, strlen(FTP_CMD_RMD)) == 0) {
        printf("FTP: Suppression de répertoire: %.*s\n", 
               (int)(end - (data + strlen(FTP_CMD_RMD) + 1)), 
               data + strlen(FTP_CMD_RMD) + 1);
    }
    else if (strncmp(data, FTP_CMD_DELE, strlen(FTP_CMD_DELE)) == 0) {
        printf("FTP: Suppression de fichier: %.*s\n", 
               (int)(end - (data + strlen(FTP_CMD_DELE) + 1)), 
               data + strlen(FTP_CMD_DELE) + 1);
    }
    else if (strncmp(data, FTP_CMD_QUIT, strlen(FTP_CMD_QUIT)) == 0) {
        printf("FTP: Déconnexion\n");
    }
    else if (strncmp(data, FTP_CMD_PWD, strlen(FTP_CMD_PWD)) == 0) {
        printf("FTP: Demande du répertoire courant\n");
    }
    else if (packet_len > 0) {
        // Afficher les autres données FTP
        printf("FTP: Données: %.*s\n", (int)packet_len, data);
    }
}









