#include "netshark.h"
#include "netshark_types.h"
#include <errno.h>
#include <dirent.h>

// Implémentation améliorée de netshark_findalldevs
int netshark_findalldevs(netshark_if_t **alldevsp, char *errbuf) {
    DIR *dir;
    struct dirent *entry;
    netshark_if_t *devlist = NULL;
    netshark_if_t *last_dev = NULL;
    
    // Ouvrir le répertoire /sys/class/net pour lister les interfaces
    dir = opendir("/sys/class/net");
    if (dir == NULL) {
        snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "Cannot open /sys/class/net: %s", strerror(errno));
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer . et ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
            
        // Créer une nouvelle interface
        netshark_if_t *dev = malloc(sizeof(netshark_if_t));
        if (dev == NULL) {
            snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "malloc failed");
            closedir(dir);
            return -1;
        }
        
        dev->name = strdup(entry->d_name);
        dev->description = strdup("Network interface");
        dev->addresses = NULL;
        dev->flags = 0;
        dev->next = NULL;
        
        // Ajouter à la liste
        if (devlist == NULL) {
            devlist = dev;
        } else {
            last_dev->next = dev;
        }
        last_dev = dev;
    }
    
    closedir(dir);
    *alldevsp = devlist;
    return 0;
}

// Implémentation simplifiée de netshark_open_live
netshark_t *netshark_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf) {
    (void)device;   // Éviter les warnings
    (void)snaplen;
    (void)promisc;
    (void)to_ms;
    
    netshark_t *p = malloc(sizeof(struct netshark_t));
    if (p == NULL) {
        snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "malloc failed");
        return NULL;
    }
    
    // Initialisation basique
    p->activated = 1;
    p->linktype = DLT_EN10MB; // Ethernet par défaut
    p->errbuf = errbuf;
    
    return p;
}

// Implémentation de netshark_datalink
int netshark_datalink(netshark_t *p) {
    if (!p->activated)
        return -1; // Error code
    return p->linktype;
}

// Implémentation simplifiée de netshark_compile
int netshark_compile(netshark_t *p, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask) {
    (void)p;        // Éviter les warnings
    (void)buf;
    (void)optimize;
    (void)mask;
    
    // Pour simplifier, on accepte tous les filtres
    program->bf_insns = NULL;
    program->bf_len = 0;
    return 0;
}

// Implémentation de netshark_geterr
const char *netshark_geterr(netshark_t *p) {
    return p->errbuf;
}

// Implémentation de netshark_close
void netshark_close(netshark_t *p) {
    if (p) {
        free(p);
    }
}

// Implémentation de netshark_freealldevs
void netshark_freealldevs(netshark_if_t *alldevs) {
    netshark_if_t *curdev, *nextdev;
    netshark_addr_t *curaddr, *nextaddr;

    for (curdev = alldevs; curdev != NULL; curdev = nextdev) {
        nextdev = curdev->next;

        for (curaddr = curdev->addresses; curaddr != NULL; curaddr = nextaddr) {
            nextaddr = curaddr->next;
            if (curaddr->addr)
                free(curaddr->addr);
            if (curaddr->netmask)
                free(curaddr->netmask);
            if (curaddr->broadaddr)
                free(curaddr->broadaddr);
            if (curaddr->dstaddr)
                free(curaddr->dstaddr);
            free(curaddr);
        }

        if (curdev->name)
            free(curdev->name);
        if (curdev->description)
            free(curdev->description);
        free(curdev);
    }
}

// Implémentation de netshark_setfilter
int netshark_setfilter(netshark_t *p, struct bpf_program *fp) {
    (void)p;    // Éviter les warnings
    (void)fp;
    
    // Pour simplifier, on accepte tous les filtres
    return 0;
}

// Implémentation de netshark_freecode
void netshark_freecode(struct bpf_program *fp) {
    if (fp->bf_insns != NULL) {
        free(fp->bf_insns);
        fp->bf_insns = NULL;
    }
    fp->bf_len = 0;
}

// Implémentation de netshark_lookupnet
int netshark_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf) {
    struct ifreq ifr;
    struct sockaddr_in *sin4;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "socket: %s", strerror(errno));
        return (-1);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "ioctl(SIOCGIFADDR): %s", strerror(errno));
        close(fd);
        return (-1);
    }

    sin4 = (struct sockaddr_in *)&ifr.ifr_addr;
    *netp = sin4->sin_addr.s_addr;

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "ioctl(SIOCGIFNETMASK): %s", strerror(errno));
        close(fd);
        return (-1);
    }

    sin4 = (struct sockaddr_in *)&ifr.ifr_netmask;
    *maskp = sin4->sin_addr.s_addr;

    close(fd);
    return (0);
}

// Implémentation simplifiée de netshark_loop
int netshark_loop(netshark_t *p, int cnt, netshark_handler callback, u_char *user) {
    (void)p;    // Éviter les warnings
    (void)cnt;
    
    // Pour simplifier, on simule la capture d'un paquet
    struct netshark_pkthdr header;
    u_char packet[64]; // Paquet factice
    
    // Simuler un en-tête de paquet
    header.ts.tv_sec = time(NULL);
    header.ts.tv_usec = 0;
    header.caplen = sizeof(packet);
    header.len = sizeof(packet);
    
    // Remplir le paquet avec des données factices
    memset(packet, 0, sizeof(packet));
    
    // Appeler le callback avec le paquet simulé
    callback(user, &header, packet);
    
    return 1; // Un paquet traité
} 