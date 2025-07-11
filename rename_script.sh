#!/bin/bash

# Script pour renommer tous les fichiers et symboles de pcap vers netshark
# Usage: ./rename_script.sh

echo "Début du renommage des fichiers et symboles..."

# 1. Renommer les fichiers .c et .h
cd netsharkcap

# Renommer les fichiers principaux
mv pcap.c netshark.c
mv pcap.h netshark.h

# 2. Remplacer tous les symboles pcap_ par netshark_ dans tous les fichiers
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's/pcap_/netshark_/g' {} \;

# 3. Remplacer les includes
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's/#include "pcap\.h"/#include "netshark.h"/g' {} \;
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's/#include <pcap\.h>/#include "netshark.h"/g' {} \;

# 4. Remplacer les noms de fonctions dans les commentaires et chaînes
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's/PCAP_/NETSHARK_/g' {} \;

# 5. Remplacer les noms de variables et structures
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's/struct pcap_/struct netshark_/g' {} \;
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's/typedef pcap_/typedef netshark_/g' {} \;

echo "Renommage terminé !"
