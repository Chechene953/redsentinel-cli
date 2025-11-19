# 🚀 RedSentinel v7.0 - Nouveau CLI Professionnel

## ⚡ Changement Important

RedSentinel v7.0 introduit un **tout nouveau CLI** basé sur **Click** avec des commandes modernes et professionnelles!

## 📦 Réinstallation Nécessaire

Pour obtenir les nouvelles fonctionnalités, **réinstallez RedSentinel**:

### Sur Linux:
```bash
cd /home/alext/redsentinel-cli
sudo bash install.sh
```

### Sur Windows:
```powershell
cd C:\Users\alext\redsentinel-cli
pip install -e . --force-reinstall
```

## 🎯 Nouvelles Commandes Disponibles

### 1️⃣ **Reconnaissance** (`redsentinel recon`)

```bash
# Découverte de sous-domaines
redsentinel recon subdomains example.com --deep

# Scan de ports professionnel
redsentinel recon portscan example.com --top
redsentinel recon portscan 192.168.1.10 --ports 1-1000 --service-detection

# Analyse DNS complète
redsentinel recon dns example.com

# Audit SSL/TLS
redsentinel recon ssl example.com --port 443

# Pipeline complet de reconnaissance
redsentinel recon full example.com
```

### 2️⃣ **Scan de Vulnérabilités** (`redsentinel vuln`)

```bash
# Scan Nuclei
redsentinel vuln nuclei https://example.com --severity critical,high

# Scan Nikto
redsentinel vuln nikto https://example.com

# Détection et scan CMS (WordPress, Joomla, Drupal)
redsentinel vuln cms https://example.com

# Recherche de CVE
redsentinel vuln cve "apache 2.4.49"
```

### 3️⃣ **OSINT** (`redsentinel osint`)

```bash
# Collecte d'informations complète
redsentinel osint gather example.com --emails --github --pastebin

# Découverte d'assets cloud (AWS, Azure, GCP)
redsentinel osint cloud example.com
```

### 4️⃣ **Exploitation** (`redsentinel exploit`)

⚠️ **Autorisation requise uniquement!**

```bash
# Brute-force de répertoires
redsentinel exploit dirbrute https://example.com --wordlist /path/to/wordlist.txt

# Craquage de hash
redsentinel exploit hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5

# Recherche d'exploits
redsentinel exploit search "apache 2.4.49"
```

### 5️⃣ **Rapports** (`redsentinel report`)

```bash
# Génération de rapport HTML
redsentinel report generate scan_results.json --format html

# Génération de rapport PDF
redsentinel report generate scan_results.json --format pdf

# Génération de rapport Markdown
redsentinel report generate scan_results.json --format md
```

### 6️⃣ **Workflows** (`redsentinel workflow`)

```bash
# Lister les workflows disponibles
redsentinel workflow list

# Exécuter un workflow
redsentinel workflow run webapp-audit example.com
```

### 7️⃣ **Workspaces** (`redsentinel workspace`)

```bash
# Créer un workspace
redsentinel workspace create "Audit_Client_X"

# Lister les workspaces
redsentinel workspace list
```

### 8️⃣ **Interfaces** 

```bash
# Menu interactif (ancien style)
redsentinel-menu

# Interface TUI moderne
redsentinel tui

# Interface graphique
redsentinel gui
```

## 📋 Comparaison Ancien vs Nouveau

### ❌ Ancien (v6.0)
```bash
redsentinel
# → Menu interactif uniquement
# → Pas de commandes CLI directes
```

### ✅ Nouveau (v7.0)
```bash
# Mode par défaut: CLI moderne
redsentinel --help

# Commandes directes
redsentinel recon subdomains example.com
redsentinel vuln nuclei https://example.com

# Menu interactif toujours disponible
redsentinel         # → Lance le menu si aucun argument
redsentinel-menu    # → Force le menu interactif
```

## 🎨 Structure des Commandes

```
redsentinel
├── --version          # Version
├── --help             # Aide
├── recon              # Reconnaissance
│   ├── subdomains     # Sous-domaines
│   ├── portscan       # Scan de ports
│   ├── dns            # Analyse DNS
│   ├── ssl            # Audit SSL/TLS
│   └── full           # Pipeline complet
├── vuln               # Vulnérabilités
│   ├── nuclei         # Scan Nuclei
│   ├── nikto          # Scan Nikto
│   ├── cms            # Détection CMS
│   └── cve            # Recherche CVE
├── osint              # OSINT
│   ├── gather         # Collecte info
│   └── cloud          # Assets cloud
├── exploit            # Exploitation
│   ├── dirbrute       # Brute-force
│   ├── hash           # Craquage hash
│   └── search         # Recherche exploits
├── report             # Rapports
│   └── generate       # Génération
├── workflow           # Workflows
│   ├── list           # Lister
│   └── run            # Exécuter
├── workspace          # Workspaces
│   ├── create         # Créer
│   └── list           # Lister
├── interactive        # Menu interactif
├── tui                # Interface TUI
├── gui                # Interface GUI
└── update             # Vérifier updates
```

## 🔧 Options Globales

Toutes les commandes supportent:

```bash
# Sauvegarder les résultats
--output <file>        # -o <file>

# Format de sortie
--format <format>      # -f <format>

# Verbose
--verbose              # -v

# Aide spécifique
--help                 # -h
```

## 💡 Exemples d'Utilisation

### Audit Web Complet

```bash
# 1. Reconnaissance
redsentinel recon full example.com -o recon.json

# 2. Scan vulnérabilités
redsentinel vuln nuclei https://example.com -o vuln.json

# 3. Générer rapport
redsentinel report generate vuln.json --format pdf -o audit_report.pdf
```

### OSINT Complet

```bash
# Collecte toutes les informations
redsentinel osint gather example.com \
  --emails \
  --github \
  --pastebin \
  -o osint_results.json

# Assets cloud
redsentinel osint cloud example.com -o cloud_assets.json
```

### Pipeline Automatisé

```bash
# Utiliser un workflow prédéfini
redsentinel workflow run webapp-audit example.com
```

## 🔄 Migration depuis v6.0

Si vous utilisez des scripts avec l'ancien RedSentinel:

### Avant (v6.0)
```bash
# Pas de CLI directe
# Toujours interactif
```

### Après (v7.0)
```bash
# Utilisez les nouvelles commandes
redsentinel recon subdomains $TARGET
redsentinel vuln nuclei https://$TARGET

# Ou gardez le menu interactif
redsentinel-menu
```

## 📚 Documentation

- **Guide rapide**: `QUICK_START.md`
- **Installation Linux**: `INSTALL_LINUX.md`
- **Installation Windows**: `INSTALL_WINDOWS.md`
- **Changelog**: `CHANGELOG_V7.md`

## ✅ Vérification après Installation

```bash
# 1. Version
redsentinel --version
# → RedSentinel v7.0.0

# 2. Aide
redsentinel --help
# → Affiche toutes les commandes disponibles

# 3. Test d'une commande
redsentinel recon dns google.com
# → Devrait fonctionner!

# 4. Menu interactif
redsentinel
# → Lance le menu si pas d'arguments
```

## 🐛 Si les commandes ne fonctionnent toujours pas

```bash
# Forcer la réinstallation
pip uninstall redsentinel
pip install -e . --force-reinstall

# Vérifier le point d'entrée
which redsentinel  # Linux
where redsentinel  # Windows

# Relancer l'installation
sudo bash install.sh  # Linux
```

---

**🔴 RedSentinel v7.0 - MACHINE DE GUERRE CYBER**

**Nouveau CLI professionnel avec 50+ commandes!** 🚀

