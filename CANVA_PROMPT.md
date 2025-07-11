# PROMPT CANVA - NETSHARK 2600

## 🎨 Style et Thème
Créez une présentation professionnelle avec un thème cybersécurité/réseau :
- **Couleurs principales** : Bleu foncé (#1a365d), Vert cybersécurité (#00ff88), Gris technique (#2d3748)
- **Style** : Moderne, technique, professionnel
- **Typographie** : Police monospace pour le code, police moderne pour le texte
- **Éléments visuels** : Icônes réseau, diagrammes de flux, captures d'écran de terminal

## 📋 Structure de la Présentation

### Slide 1 : Page de Titre
**Titre** : "NETSHARK 2600"
**Sous-titre** : "Analyseur de Paquets Réseau Avancé"
**Éléments** :
- Logo ASCII art de Netshark (bannière du README)
- Icônes : réseau, bouclier, code
- Équipe : Jonathan Tondelier, Elie Marouani, Jeremy Dufresne, Loris Danel

### Slide 2 : Problématique
**Titre** : "Pourquoi Netshark ?"
**Contenu** :
- Besoin d'analyse réseau en temps réel
- Outils existants trop complexes (Wireshark)
- Nécessité d'un outil simple et efficace
- Apprentissage des protocoles réseau

### Slide 3 : Fonctionnalités Principales
**Titre** : "🚀 Fonctionnalités"
**Contenu** (avec icônes) :
- 🔍 Capture en temps réel
- 📊 Analyse multi-protocoles (TCP, UDP, ARP, HTTP, FTP)
- 🛡️ Filtrage BPF intégré
- ⚡ Performance optimisée
- 🎯 Interface simple

### Slide 4 : Architecture Technique
**Titre** : "🏗️ Architecture Modulaire"
**Diagramme** :
```
┌─────────────────┐
│   Interface     │
│   Utilisateur   │
└─────────┬───────┘
          │
┌─────────▼───────┐
│   Initialisation│
│   (init.c)      │
└─────────┬───────┘
          │
┌─────────▼───────┐
│   Handlers      │
│   Spécialisés   │
└─────────┬───────┘
          │
┌─────────▼───────┐
│   Parsers       │
│   Protocoles    │
└─────────────────┘
```

### Slide 5 : Protocoles Supportés
**Titre** : "📦 Protocoles Analysés"
**Grille avec icônes** :
- **TCP** : Segments, flags, ports, séquences
- **UDP** : Datagrammes, ports
- **ARP** : Résolution d'adresses
- **HTTP** : Requêtes/réponses web
- **FTP** : Commandes de transfert

### Slide 6 : Démonstration
**Titre** : "🎯 Démonstration"
**Capture d'écran** :
```bash
$ sudo ./netshark -i eth0 -f http
=== HTTP Request ===
Method: GET
Path: /api/data
Version: HTTP/1.1
Headers:
Host: api.example.com
User-Agent: Mozilla/5.0
==========================
```

### Slide 7 : Installation et Utilisation
**Titre** : "⚙️ Installation Simple"
**Étapes** :
1. `sudo apt-get install libpcap-dev`
2. `git clone https://github.com/NetCore2600/Netshark.git`
3. `make`
4. `sudo ./netshark -i eth0 -f tcp`

### Slide 8 : Avantages Techniques
**Titre** : "💡 Avantages"
**Liste** :
- ✅ Architecture modulaire
- ✅ Performance optimisée
- ✅ Code source propre
- ✅ Documentation complète
- ✅ Support multi-protocoles
- ✅ Interface simple

### Slide 9 : Cas d'Usage
**Titre** : "🔍 Cas d'Usage"
**Scénarios** :
- **Débogage réseau** : Identifier les problèmes de connectivité
- **Analyse de sécurité** : Détecter les activités suspectes
- **Apprentissage** : Comprendre les protocoles réseau
- **Monitoring** : Surveiller le trafic en temps réel

### Slide 10 : Équipe et Contribution
**Titre** : "👥 Équipe de Développement"
**Membres** :
- **Jonathan Tondelier** : Architecture et développement
- **Elie Marouani** : Analyse de protocoles
- **Jeremy Dufresne** : Handlers et parsers
- **Loris Danel** : Interface et tests

### Slide 11 : Technologies Utilisées
**Titre** : "🛠️ Stack Technique"
**Technologies** :
- **Langage** : C99
- **Bibliothèque** : libpcap
- **Système** : Linux
- **Compilateur** : GCC
- **Build** : Make

### Slide 12 : Conclusion
**Titre** : "🎯 Conclusion"
**Points clés** :
- Outil puissant et simple
- Architecture modulaire
- Support multi-protocoles
- Code source ouvert
- Documentation complète

## 🎨 Éléments Visuels à Inclure

### Icônes Suggérées
- 🔍 Loupe (analyse)
- 📦 Boîte (modules)
- ⚡ Éclair (performance)
- 🛡️ Bouclier (sécurité)
- 🌐 Globe (réseau)
- 💻 Ordinateur (technique)
- 📊 Graphique (statistiques)
- 🔧 Clé à molette (outils)

### Couleurs Recommandées
- **Primaire** : #1a365d (bleu foncé)
- **Secondaire** : #00ff88 (vert cybersécurité)
- **Accent** : #2d3748 (gris technique)
- **Arrière-plan** : #f7fafc (gris clair)
- **Texte** : #1a202c (noir)

### Typographie
- **Titres** : Police moderne, gras
- **Code** : Police monospace (Courier New, Monaco)
- **Texte** : Police lisible (Arial, Helvetica)

## 📝 Notes pour la Présentation

### Points Clés à Souligner
1. **Simplicité** : Interface simple vs Wireshark complexe
2. **Performance** : Optimisé en C, rapide
3. **Modularité** : Architecture extensible
4. **Éducatif** : Parfait pour apprendre les réseaux
5. **Professionnel** : Code propre, documentation complète

### Éléments Interactifs
- Démonstration en direct si possible
- Capture d'écran du terminal
- Diagrammes d'architecture
- Exemples de sortie

### Durée Suggérée
- **Présentation** : 10-15 minutes
- **Questions** : 5-10 minutes
- **Démonstration** : 5 minutes

## 🎯 Objectifs de la Présentation

1. **Expliquer** le projet et ses objectifs
2. **Démontrer** les fonctionnalités
3. **Montrer** l'architecture technique
4. **Convaincre** de la qualité du code
5. **Inspirer** pour les contributions futures

---

**Utilisez ce prompt avec l'IA de Canva pour créer une présentation professionnelle et engageante de votre projet Netshark 2600 !** 