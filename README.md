# NETSHARK - Analyseur de Paquets Réseau Minimaliste

```
███╗   ██╗███████╗████████╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗    ██████╗  ██████╗  ██████╗  ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝    ╚════██╗██╔════╝ ██╔═████╗██╔═████╗
██╔██╗ ██║█████╗     ██║   ███████╗███████║███████║██████╔╝█████╔╝      █████╔╝███████╗ ██║██╔██║██║██╔██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗     ██╔═══╝ ██╔═══██╗████╔╝██║████╔╝██║
██║ ╚████║███████╗   ██║   ███████║██║  ██║██║  ██║██║  ██║██║  ██╗    ███████╗╚██████╔╝╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ 
```

## 🎯 Vue d'ensemble

**Netshark** est un analyseur de paquets réseau minimaliste inspiré de Wireshark, conçu pour capturer et analyser le trafic réseau **sans dépendance à libpcap**. Il utilise directement les sockets raw Linux pour une capture native et efficace.

### ✨ Caractéristiques Principales

- 🔥 **Capture native** : Utilise `AF_PACKET` et `ETH_P_ALL` (Linux)
- 🚫 **Zéro dépendance** : Aucune libpcap requise
- 🎯 **Filtrage intelligent** : TCP, UDP, HTTP/HTTPS, ou tout le trafic
- 📊 **Affichage détaillé** : Adresses IP, ports, tailles, protocoles
- ⚡ **Performance optimale** : Capture en temps réel sans overhead
- 🛡️ **Architecture simple** : Code minimaliste et maintenable

## 🚀 Installation et Utilisation

### Prérequis
- Linux (testé sur Debian/Ubuntu)
- Compilateur GCC
- Privilèges root pour la capture de paquets

### Compilation
```bash
git clone <repository>
cd Netshark
make clean && make
```

### Utilisation
```bash
# Capture TCP uniquement
sudo ./netshark -i wlp0s20f3 -f tcp

# Capture UDP uniquement  
sudo ./netshark -i wlp0s20f3 -f udp

# Capture HTTP/HTTPS uniquement
sudo ./netshark -i wlp0s20f3 -f http

# Capture tout le trafic
sudo ./netshark -i wlp0s20f3 -f all
```

## 🔧 Comment ça marche (Sans libpcap)

### 1. **Capture Native Linux**

Netshark utilise directement les sockets raw Linux au lieu de libpcap :

```c
// Création du socket raw pour capturer tous les paquets Ethernet
sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```

**Avantages :**
- ✅ Aucune dépendance externe
- ✅ Performance native
- ✅ Contrôle total sur la capture
- ✅ Compatible avec tous les kernels Linux

### 2. **Architecture de Capture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Interface     │───▶│  Socket Raw     │───▶│  Filtrage       │
│   Réseau        │    │  AF_PACKET      │    │  Côté Utilisateur│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Parsing        │
                       │  Headers        │
                       │  IP/TCP/UDP     │
                       └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Affichage      │
                       │  Formaté        │
                       └─────────────────┘
```

### 3. **Processus de Capture**

1. **Initialisation** : Création du socket raw avec `AF_PACKET`
2. **Binding** : Liaison à l'interface réseau spécifiée
3. **Capture** : Boucle `recvfrom()` pour recevoir les paquets
4. **Parsing** : Analyse des en-têtes Ethernet → IP → TCP/UDP
5. **Filtrage** : Application des filtres côté utilisateur
6. **Affichage** : Formatage et affichage des informations

### 4. **Parsing des Headers**

```c
// 1. Header Ethernet (14 bytes)
const struct ethhdr *eth = (const struct ethhdr *)buffer;
if (ntohs(eth->h_proto) != ETH_P_IP) continue; // IPv4 seulement

// 2. Header IP (variable selon IHL)
const struct iphdr *iph = (const struct iphdr *)(buffer + sizeof(struct ethhdr));

// 3. Header TCP/UDP
const struct tcphdr *tcp = (const struct tcphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*4);
```

### 5. **Filtrage Intelligent**

**Filtrage côté utilisateur** (pas de BPF) :
- `-f tcp` : Seulement les paquets TCP
- `-f udp` : Seulement les paquets UDP  
- `-f http` : TCP sur ports 80/443
- `-f all` : Tous les paquets IP

### 6. **Détection HTTP/HTTPS**

```c
// Détection automatique des ports HTTP/HTTPS
if (src_port == 80 || dst_port == 80) {
    printf(" [HTTP]");
} else if (src_port == 443 || dst_port == 443) {
    printf(" [HTTPS]");
}
```

## 📁 Structure du Projet

```
Netshark/
├── src/
│   └── main.c          # Code principal (capture + parsing)
├── include/            # Headers système (pas de headers custom)
├── netsharkcap/        # Intégration libpcap (optionnelle)
├── Makefile           # Compilation simple
└── README.md          # Documentation
```

## 🔍 Exemples de Sortie

### Capture TCP
```
IP 172.31.28.141 -> 44.195.225.72 TCP 37830 -> 443 (Taille: 74)
IP 44.195.225.72 -> 172.31.28.141 TCP 443 -> 37830 (Taille: 74)
```

### Capture HTTP
```
IP 172.31.28.141 -> 104.18.18.125 TCP 46008 -> 443 [HTTPS] (Taille: 1031)
IP 104.18.18.125 -> 172.31.28.141 TCP 443 -> 46008 [HTTPS] (Taille: 101)
```

## 🆚 Comparaison avec libpcap

| Aspect | Netshark (Sans libpcap) | Avec libpcap |
|--------|-------------------------|--------------|
| **Dépendances** | Aucune | libpcap-dev |
| **Performance** | Native Linux | Overhead libpcap |
| **Contrôle** | Total | Limité par libpcap |
| **Portabilité** | Linux uniquement | Multi-plateforme |
| **Simplicité** | Code minimaliste | API complexe |
| **Maintenance** | Facile | Dépendant de libpcap |

## 🛠️ Développement

### Compilation
```bash
make clean && make
```

### Debug
```bash
gcc -Wall -Wextra -g src/main.c -o netshark
```

### Test
```bash
# Générer du trafic HTTP
curl http://example.com

# Générer du trafic HTTPS  
curl https://www.google.com

# Capturer en temps réel
sudo ./netshark -i wlp0s20f3 -f http
```

## 🎯 Avantages de l'Approche Sans libpcap

1. **Simplicité** : Code direct et compréhensible
2. **Performance** : Pas d'overhead de libpcap
3. **Contrôle** : Gestion native des sockets Linux
4. **Indépendance** : Aucune dépendance externe
5. **Apprentissage** : Compréhension profonde du réseau
6. **Maintenance** : Code minimaliste et robuste

## 📝 Licence

Projet éducatif - Libre d'utilisation et de modification.

---

**Netshark** : Capture réseau native, sans compromis ! 🔥
