### NETSHARK 2600
```
███╗   ██╗███████╗████████╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗    ██████╗  ██████╗  ██████╗  ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝    ╚════██╗██╔════╝ ██╔═████╗██╔═████╗
██╔██╗ ██║█████╗     ██║   ███████╗███████║███████║██████╔╝█████╔╝      █████╔╝███████╗ ██║██╔██║██║██╔██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗     ██╔═══╝ ██╔═══██╗████╔╝██║████╔╝██║
██║ ╚████║███████╗   ██║   ███████║██║  ██║██║  ██║██║  ██║██║  ██╗    ███████╗╚██████╔╝╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ 
```

## 📋 Description

**Netshark 2600** est un analyseur de paquets réseau avancé développé en C, inspiré de Wireshark. Il permet la capture et l'analyse en temps réel du trafic réseau avec un support complet des protocoles TCP/IP, UDP, ARP, HTTP et FTP.

## 🚀 Fonctionnalités

### 🔍 **Capture de Paquets**
- Capture en temps réel sur n'importe quelle interface réseau
- Mode promiscuité pour capturer tout le trafic
- Filtrage BPF (Berkeley Packet Filter) intégré
- Support des interfaces Ethernet et NULL

### 📊 **Analyse de Protocoles**
- **TCP** : Analyse complète des en-têtes, flags, ports, séquences
- **UDP** : Analyse des datagrammes et ports
- **ARP** : Résolution d'adresses et analyse des requêtes/réponses
- **HTTP** : Analyse des requêtes et réponses HTTP (GET, POST, etc.)
- **FTP** : Analyse des commandes et réponses FTP

### 🛠️ **Fonctionnalités Avancées**
- Architecture modulaire avec handlers spécialisés
- Parsers dédiés pour chaque protocole
- Affichage détaillé des en-têtes de paquets
- Horodatage précis des événements
- Gestion d'erreurs robuste

## 🏗️ Architecture

### Structure du Projet
```
netshark/
├── src/                    # Code source principal
│   ├── main.c             # Point d'entrée et parsing d'arguments
│   ├── init.c             # Initialisation et configuration
│   ├── handlers/          # Gestionnaires de protocoles
│   │   ├── tcp_handler.c  # Analyse TCP
│   │   ├── udp_handler.c  # Analyse UDP
│   │   ├── arp_handler.c  # Analyse ARP
│   │   ├── http_handler.c # Analyse HTTP
│   │   └── ftp_handler.c  # Analyse FTP
│   └── parsers/           # Parsers spécialisés
│       ├── tcp_parser.c   # Parser TCP
│       ├── udp_parser.c   # Parser UDP
│       ├── arp_parser.c   # Parser ARP
│       ├── http_parser.c  # Parser HTTP
│       └── ftp_parser.c   # Parser FTP
├── include/               # Fichiers d'en-tête
│   ├── netshark.h        # Interface principale
│   ├── handler.h         # Interface des handlers
│   └── parser.h          # Interface des parsers
├── build/                # Fichiers compilés
├── img/                  # Images et ressources
└── Makefile             # Configuration de compilation
```

### Composants Principaux

#### 🔧 **Initialisation (`init.c`)**
- Découverte automatique des interfaces réseau
- Configuration du handle libpcap
- Compilation et application des filtres BPF
- Sélection du handler approprié selon le protocole

#### 📦 **Handlers de Protocoles**
Chaque protocole dispose d'un handler spécialisé :
- **TCP Handler** : Analyse des segments TCP, flags, ports, séquences
- **UDP Handler** : Analyse des datagrammes UDP
- **ARP Handler** : Analyse des requêtes/réponses ARP
- **HTTP Handler** : Analyse des requêtes HTTP (GET, POST, etc.)
- **FTP Handler** : Analyse des commandes FTP

#### 🔍 **Parsers Spécialisés**
Parsers dédiés pour l'extraction et l'analyse des données de chaque protocole.

## 📦 Installation

### Prérequis
- **Système** : Linux (testé sur Debian/Ubuntu, CentOS/RHEL)
- **Compilateur** : GCC avec support C99
- **Bibliothèques** : libpcap-dev

### Installation des Dépendances

#### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install libpcap-dev build-essential
```

#### CentOS/RHEL
```bash
sudo yum install libpcap-devel gcc make
```

### Compilation

1. **Cloner le Repository**
   ```bash
   git clone https://github.com/NetCore2600/Netshark.git
   cd Netshark
   ```

2. **Compiler le Projet**
   ```bash
   make
   ```

3. **Vérifier l'Installation**
   ```bash
   ./netshark --help
   ```

## 🎯 Utilisation

### Syntaxe de Base
```bash
sudo ./netshark -i <interface> -f <filtre>
```

### Exemples d'Utilisation

#### Capture TCP
```bash
sudo ./netshark -i eth0 -f tcp
```

#### Capture HTTP
```bash
sudo ./netshark -i eth0 -f http
```

#### Capture FTP
```bash
sudo ./netshark -i eth0 -f ftp
```

#### Capture UDP
```bash
sudo ./netshark -i eth0 -f udp
```

#### Capture ARP
```bash
sudo ./netshark -i eth0 -f arp
```

### Filtres Supportés
- `tcp` : Capture uniquement le trafic TCP
- `udp` : Capture uniquement le trafic UDP
- `http` : Capture le trafic HTTP (ports 80/8080)
- `ftp` : Capture le trafic FTP (port 21)
- `arp` : Capture les paquets ARP

## 🔧 Configuration

### Permissions
Le programme nécessite des privilèges root pour capturer les paquets réseau :
```bash
sudo ./netshark -i eth0 -f tcp
```

### Interfaces Disponibles
Pour lister les interfaces disponibles :
```bash
ip link show
```

## 📊 Sortie d'Exemple

### Analyse TCP
```
=== TCP Packet Analysis ===
Source IP: 192.168.1.100
Destination IP: 8.8.8.8
Source Port: 54321
Destination Port: 80
Sequence Number: 1234567890
Acknowledgment Number: 987654321
Window Size: 65535
TCP Flags: SYN
Header Length: 20 bytes
Data Length: 0 bytes
Total Packet Length: 60 bytes
==========================
```

### Analyse HTTP
```
[14:30:25] HTTP 192.168.1.100:54321 -> 8.8.8.8:80
=== HTTP Request ===
Method: GET
Path: /api/data
Version: HTTP/1.1

Headers:
Host: api.example.com
User-Agent: Mozilla/5.0
Accept: application/json
==========================
```

## 🛠️ Développement

### Structure du Code

#### Point d'Entrée (`main.c`)
- Parsing des arguments en ligne de commande
- Initialisation de l'application
- Boucle principale de capture

#### Initialisation (`init.c`)
- Découverte des interfaces réseau
- Configuration du handle libpcap
- Compilation des filtres BPF
- Sélection des handlers

#### Handlers (`handlers/`)
Chaque handler implémente la signature :
```c
void protocol_handler(unsigned char *args, 
                     const struct pcap_pkthdr *header, 
                     const unsigned char *packet);
```

### Compilation
```bash
make clean    # Nettoyer les fichiers compilés
make          # Compiler le projet
make install  # Installer (si configuré)
```

## 🔍 Dépannage

### Erreurs Communes

#### Interface Non Trouvée
```bash
Error: Interface eth0 not found
```
**Solution** : Vérifier le nom de l'interface avec `ip link show`

#### Permissions Insuffisantes
```bash
Error: Couldn't open device eth0: Permission denied
```
**Solution** : Exécuter avec `sudo`

#### Bibliothèque Manquante
```bash
Error: libpcap not found
```
**Solution** : Installer `libpcap-dev`

## 🤝 Contribution

### Équipe de Développement
- **Jonathan Tondelier** - Architecture et développement
- **Elie Marouani** - Analyse de protocoles
- **Jeremy Dufresne** - Handlers et parsers
- **Loris Danel** - Interface et tests

### Guidelines
1. Respecter les conventions de nommage
2. Ajouter des commentaires pour les fonctions complexes
3. Tester sur différentes distributions Linux
4. Documenter les nouvelles fonctionnalités

## 📄 Licence

Ce projet est développé dans le cadre du cours de réseaux informatiques.

## 🔗 Liens Utiles

- **libpcap** : https://www.tcpdump.org/
- **BPF** : https://www.tcpdump.org/manpages/pcap-filter.7.html
- **Wireshark** : https://www.wireshark.org/

---

**Netshark 2600** - Analyseur de paquets réseau avancé pour l'analyse et le débogage du trafic réseau. 