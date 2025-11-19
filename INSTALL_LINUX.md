# Installation RedSentinel v7.0 sur Linux

## 🚀 Installation Rapide

### Méthode 1: Installation Automatique (Recommandée)

```bash
# Cloner le dépôt
git clone https://github.com/votre-repo/redsentinel-cli.git
cd redsentinel-cli

# Lancer l'installation
sudo bash install.sh
```

**La commande `redsentinel` sera disponible globalement!**

### Méthode 2: Installation Manuelle

```bash
# Cloner le dépôt
git clone https://github.com/votre-repo/redsentinel-cli.git
cd redsentinel-cli

# Créer un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt

# Installer RedSentinel en mode développement
pip install -e .
```

**Lancer avec:**
```bash
# Si vous êtes dans le venv
redsentinel

# Ou avec Python directement
python -m redsentinel

# Ou avec le script
python run.py
```

## ✅ Vérification de l'Installation

```bash
# Vérifier la version
redsentinel --version
# Sortie attendue: RedSentinel v7.0.0

# Vérifier avec Python
python3 -c "from redsentinel import __version__; print(f'Version: {__version__}')"
# Sortie attendue: Version: 7.0.0
```

## 🔧 Utilisation

### Lancer RedSentinel

```bash
# Mode interactif (menu)
redsentinel

# Avec options CLI
redsentinel --help
```

### Commandes Principales

```bash
# Reconnaissance
redsentinel recon subdomains example.com
redsentinel recon portscan example.com

# Scan de vulnérabilités
redsentinel vuln nuclei https://example.com
redsentinel vuln cms https://example.com

# OSINT
redsentinel osint gather example.com

# Génération de rapports
redsentinel report generate scan_results.json --format pdf
```

## 📍 Emplacements des Fichiers

- **Installation**: `~/redsentinel-auto/`
- **Virtualenv**: `~/redsentinel-auto/.venv/`
- **Launcher global**: `/usr/local/bin/redsentinel`
- **Configuration**: `~/.redsentinel/config.yaml`
- **Base de données**: `~/.redsentinel/redsentinel.db`

## 🐛 Dépannage

### La commande `redsentinel` n'est pas trouvée

```bash
# Vérifier que /usr/local/bin est dans le PATH
echo $PATH | grep "/usr/local/bin"

# Si non, ajouter à ~/.bashrc ou ~/.zshrc
export PATH="/usr/local/bin:$PATH"
source ~/.bashrc  # ou ~/.zshrc
```

### Erreur d'importation de modules

```bash
# Réinstaller les dépendances
cd ~/redsentinel-auto
source .venv/bin/activate
pip install -r requirements.txt --force-reinstall
```

### Problèmes de permissions

```bash
# Donner les permissions d'exécution
sudo chmod +x /usr/local/bin/redsentinel
```

## 🔄 Mise à Jour

```bash
cd ~/redsentinel-auto
git pull
source .venv/bin/activate
pip install -r requirements.txt --upgrade
pip install -e . --upgrade
```

## 📦 Dépendances Système

RedSentinel nécessite certains outils externes:

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y nmap masscan nikto nuclei ffuf hydra hashcat john

# Fedora/RHEL
sudo dnf install -y nmap masscan nikto nuclei ffuf hydra hashcat john

# Arch Linux
sudo pacman -S nmap masscan nikto nuclei ffuf hydra hashcat john
```

## 🆘 Support

En cas de problème:

1. Vérifier les logs: `~/.redsentinel/logs/`
2. Lancer en mode verbose: `redsentinel --verbose`
3. Consulter: [Documentation complète](https://redsentinel.fr)
4. Ouvrir une issue: [GitHub Issues](https://github.com/votre-repo/redsentinel-cli/issues)

---

**RedSentinel v7.0 - MACHINE DE GUERRE CYBER** 🔴

