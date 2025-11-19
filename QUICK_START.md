# 🚀 RedSentinel v7.0 - Guide de Démarrage Rapide

## ⚡ Lancement Rapide

### Sur Linux
```bash
# Après installation avec install.sh
redsentinel

# Ou depuis le répertoire du projet
python run.py
```

### Sur Windows
```cmd
# Avec le script batch
redsentinel.bat

# Ou avec Python
py -3.12 run.py
```

## 📋 Commandes Essentielles

### 1️⃣ Reconnaissance

```bash
# Découverte de sous-domaines
redsentinel recon subdomains example.com --deep

# Scan de ports professionnel
redsentinel recon portscan example.com --top

# Pipeline complet de reconnaissance
redsentinel recon full example.com

# Analyse DNS approfondie
redsentinel recon dns example.com

# Audit SSL/TLS
redsentinel recon ssl example.com
```

### 2️⃣ Scan de Vulnérabilités

```bash
# Scan Nuclei
redsentinel vuln nuclei https://example.com --severity critical,high

# Scan Nikto
redsentinel vuln nikto https://example.com

# Détection et scan CMS
redsentinel vuln cms https://example.com

# Recherche de CVE
redsentinel vuln cve "apache 2.4.49"
```

### 3️⃣ OSINT

```bash
# Collecte d'informations complète
redsentinel osint gather example.com --emails --github --pastebin

# Découverte d'assets cloud
redsentinel osint cloud example.com
```

### 4️⃣ Exploitation (⚠️ Autorisation Requise!)

```bash
# Brute-force de répertoires
redsentinel exploit dirbrute https://example.com

# Craquage de hash
redsentinel exploit hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5

# Recherche d'exploits
redsentinel exploit search "apache 2.4.49"
```

### 5️⃣ Génération de Rapports

```bash
# Rapport HTML
redsentinel report generate scan_results.json --format html

# Rapport PDF
redsentinel report generate scan_results.json --format pdf

# Rapport Markdown
redsentinel report generate scan_results.json --format md
```

### 6️⃣ Workflows Automatisés

```bash
# Lister les workflows disponibles
redsentinel workflow list

# Exécuter un workflow
redsentinel workflow run webapp-audit example.com
```

### 7️⃣ Gestion des Workspaces

```bash
# Créer un workspace
redsentinel workspace create "Audit_Client_X"

# Lister les workspaces
redsentinel workspace list
```

## 🎯 Exemples d'Utilisation Pratiques

### Audit Web Complet

```bash
# 1. Reconnaissance
redsentinel recon full example.com -o recon_results.json

# 2. Scan de vulnérabilités
redsentinel vuln nuclei https://example.com -o vuln_results.json

# 3. CMS Detection
redsentinel vuln cms https://example.com -o cms_results.json

# 4. Générer un rapport
redsentinel report generate vuln_results.json --format pdf -o audit_report.pdf
```

### Test de Sécurité API

```bash
# 1. Découverte d'endpoints
redsentinel exploit dirbrute https://api.example.com/v1/ -w api_wordlist.txt

# 2. Test de sécurité
redsentinel vuln nuclei https://api.example.com/v1/ -t api

# 3. Rapport JSON
redsentinel report generate api_results.json --format json
```

### Audit de Réseau

```bash
# 1. Scan de ports complet
redsentinel recon portscan 192.168.1.0/24 -p 1-65535

# 2. Identification de services
redsentinel recon portscan 192.168.1.10 --service-detection

# 3. SSL/TLS audit
redsentinel recon ssl 192.168.1.10 -p 443
```

## 🔄 Interfaces Disponibles

### Menu Interactif (Défaut)
```bash
redsentinel
# Lance le menu interactif avec toutes les options
```

### Interface CLI
```bash
redsentinel --help
# Affiche toutes les commandes disponibles
```

### TUI (Terminal User Interface)
```bash
redsentinel tui
# Lance l'interface TUI avancée avec Textual
```

### GUI (Interface Graphique)
```bash
redsentinel gui
# Lance l'interface graphique (PyQt6/Electron)
```

## 📊 Options Globales

```bash
# Afficher la version
redsentinel --version

# Mode verbose (debug)
redsentinel --verbose

# Aide générale
redsentinel --help

# Aide sur une commande spécifique
redsentinel recon --help
redsentinel vuln --help
```

## ⚙️ Configuration

### Fichier de configuration
- **Linux**: `~/.redsentinel/config.yaml`
- **Windows**: `%USERPROFILE%\.redsentinel\config.yaml`

### Variables d'environnement

```bash
# Définir le niveau de log
export REDSENTINEL_LOG_LEVEL=DEBUG

# Définir le répertoire de configuration
export REDSENTINEL_CONFIG_DIR=/custom/path

# Définir le nombre de threads
export REDSENTINEL_MAX_THREADS=20
```

## 🛡️ Considérations de Sécurité

⚠️ **IMPORTANT**:
- Utilisez RedSentinel **UNIQUEMENT** sur des systèmes pour lesquels vous avez l'autorisation
- Les tests de pénétration non autorisés sont **ILLÉGAUX**
- Respectez les lois locales et internationales
- Utilisez toujours un **VPN** et des techniques de **OPSEC**

## 📚 Ressources Complémentaires

- **Documentation complète**: [Documentation](./docs/)
- **Installation Linux**: [INSTALL_LINUX.md](INSTALL_LINUX.md)
- **Installation Windows**: [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md)
- **Changelog**: [CHANGELOG_V7.md](CHANGELOG_V7.md)
- **Roadmap**: [ROADMAP.md](ROADMAP.md)
- **Troubleshooting**: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 🆘 Besoin d'Aide?

```bash
# Vérifier l'installation
redsentinel --version

# Tester une commande simple
redsentinel recon dns google.com

# Consulter les logs
cat ~/.redsentinel/logs/redsentinel.log
```

---

**RedSentinel v7.0 - MACHINE DE GUERRE CYBER** 🔴

Bon pentest! 🎯

