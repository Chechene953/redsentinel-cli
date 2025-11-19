# ⚠️ IMPORTANT - Mise à jour vers RedSentinel v7.0

## 🔴 Problème Identifié

Vous avez remarqué que:
- ✅ La version affiche bien `7.0.0`
- ❌ Mais le menu n'a pas changé
- ❌ Les commandes `redsentinel recon`, `redsentinel vuln` etc. ne fonctionnent pas

### 🔍 Cause

Le point d'entrée de la commande `redsentinel` pointait vers **l'ancien menu** (`cli_menu.py`) au lieu du **nouveau CLI moderne** (`cli_main.py`).

## ✅ Solution - Réinstallation Rapide

### Sur Linux (RECOMMANDÉ):

```bash
# Méthode 1: Script de mise à jour automatique
cd /home/alext/redsentinel-cli
bash update_to_v7.sh
```

**OU**

```bash
# Méthode 2: Réinstallation complète
cd /home/alext/redsentinel-cli
sudo bash install.sh
```

### Vérification:

```bash
# Test 1: Version
redsentinel --version
# → RedSentinel v7.0.0

# Test 2: Aide (devrait montrer toutes les commandes)
redsentinel --help
# → Devrait afficher: recon, vuln, osint, exploit, report, workflow, etc.

# Test 3: Commande de test
redsentinel recon dns google.com
# → Devrait fonctionner!
```

## 🎯 Après la Mise à Jour

### Vous avez maintenant TROIS commandes:

1. **`redsentinel`** - Nouveau CLI moderne (recommandé)
   ```bash
   redsentinel --help
   redsentinel recon subdomains example.com
   redsentinel vuln nuclei https://example.com
   ```

2. **`redsentinel-menu`** - Ancien menu interactif
   ```bash
   redsentinel-menu
   # → Lance directement le menu interactif style v6.0
   ```

3. **`redsentinel-gui`** - Interface graphique
   ```bash
   redsentinel-gui
   # → Lance l'interface graphique
   ```

## 📋 Nouvelles Fonctionnalités Disponibles

### Commandes de Reconnaissance

```bash
# Sous-domaines
redsentinel recon subdomains example.com --deep

# Scan de ports
redsentinel recon portscan example.com --top

# DNS
redsentinel recon dns example.com

# SSL/TLS
redsentinel recon ssl example.com

# Pipeline complet
redsentinel recon full example.com
```

### Scan de Vulnérabilités

```bash
# Nuclei
redsentinel vuln nuclei https://example.com --severity critical

# Nikto
redsentinel vuln nikto https://example.com

# CMS Detection
redsentinel vuln cms https://example.com

# CVE Search
redsentinel vuln cve "apache 2.4.49"
```

### OSINT

```bash
# Collecte complète
redsentinel osint gather example.com --emails --github

# Assets cloud
redsentinel osint cloud example.com
```

### Rapports

```bash
# HTML
redsentinel report generate results.json --format html

# PDF
redsentinel report generate results.json --format pdf

# Markdown
redsentinel report generate results.json --format md
```

### Workflows

```bash
# Lister les workflows
redsentinel workflow list

# Exécuter un workflow
redsentinel workflow run webapp-audit example.com
```

## 🔄 Mode par Défaut

```bash
# Sans arguments → Lance le menu interactif
redsentinel

# Avec arguments → Utilise le CLI moderne
redsentinel recon subdomains example.com

# Force le menu → Utilise la commande dédiée
redsentinel-menu
```

## 📚 Documentation

- **Nouveau CLI**: `NOUVELLE_CLI_V7.md`
- **Guide rapide**: `QUICK_START.md`
- **Installation**: `INSTALL_LINUX.md`
- **Changelog**: `CHANGELOG_V7.md`

## 🐛 Dépannage

### Les commandes ne fonctionnent toujours pas?

```bash
# 1. Vérifier quelle version est installée
redsentinel --version

# 2. Vérifier le point d'entrée
which redsentinel
# → /usr/local/bin/redsentinel

# 3. Forcer la réinstallation
cd ~/redsentinel-auto
source .venv/bin/activate
pip uninstall redsentinel -y
pip install -e .

# 4. Recréer le launcher
sudo bash install.sh
```

### Message d'erreur "No such option"?

C'est normal si vous utilisez l'ancien menu! Réinstallez avec:
```bash
bash update_to_v7.sh
```

### Besoin de l'ancien menu?

```bash
# Toujours disponible avec:
redsentinel-menu
```

## 📊 Comparaison Avant/Après

### ❌ Avant (v6.0)
```bash
$ redsentinel
# → Menu interactif uniquement

$ redsentinel recon subdomains example.com
# → Erreur: command not found
```

### ✅ Après (v7.0)
```bash
$ redsentinel --help
# → Affiche toutes les commandes disponibles

$ redsentinel recon subdomains example.com
# → Fonctionne! Lance la reconnaissance

$ redsentinel-menu
# → Menu interactif toujours disponible
```

## 🚀 Prêt à Tester?

```bash
# 1. Mettre à jour
bash update_to_v7.sh

# 2. Tester
redsentinel --help

# 3. Première commande
redsentinel recon dns google.com

# 4. Menu interactif
redsentinel-menu
```

---

**🔴 RedSentinel v7.0 - MACHINE DE GUERRE CYBER**

**Le nouveau CLI est maintenant opérationnel!** 🎉

