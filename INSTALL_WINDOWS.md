# Installation RedSentinel v7.0 sur Windows

## 🚀 Installation Rapide

### Prérequis

- **Python 3.11 ou 3.12** (recommandé: 3.12)
- **Git** pour Windows
- **PowerShell** ou **CMD**

### Installation

```powershell
# Cloner le dépôt
git clone https://github.com/votre-repo/redsentinel-cli.git
cd redsentinel-cli

# Installer avec pip
pip install -e .
```

## ✅ Vérification de l'Installation

```powershell
# Avec Python 3.12 (si vous avez plusieurs versions)
py -3.12 -c "from redsentinel import __version__; print(f'Version: {__version__}')"
# Sortie attendue: Version: 7.0.0

# Ou avec Python par défaut
python -c "from redsentinel import __version__; print(f'Version: {__version__}')"
```

## 🔧 Utilisation sur Windows

### Méthode 1: Script Batch (Recommandée)

Le projet inclut un script batch qui gère l'encodage UTF-8:

```cmd
.\redsentinel.bat
```

### Méthode 2: Avec Python directement

```powershell
# Avec Python 3.12
py -3.12 run.py

# Ou avec Python par défaut
python run.py
```

### Méthode 3: Via le module Python

```powershell
py -3.12 -m redsentinel
```

## 📍 Emplacements des Fichiers

- **Installation**: `C:\Users\<username>\redsentinel-cli\`
- **Configuration**: `%USERPROFILE%\.redsentinel\config.yaml`
- **Base de données**: `%USERPROFILE%\.redsentinel\redsentinel.db`
- **Logs**: `%USERPROFILE%\.redsentinel\logs\`

## 🐛 Dépannage

### Erreur d'encodage / Caractères mal affichés

Le script `redsentinel.bat` règle automatiquement ce problème. Si vous lancez directement avec Python:

```powershell
# PowerShell
$env:PYTHONIOENCODING='utf-8'
py -3.12 run.py

# CMD
set PYTHONIOENCODING=utf-8
py -3.12 run.py
```

### La commande `redsentinel` n'est pas reconnue

Sur Windows, la commande n'est pas automatiquement ajoutée au PATH. Utilisez plutôt:

```powershell
# Dans le répertoire du projet
.\redsentinel.bat

# Ou
py -3.12 run.py
```

**Pour ajouter au PATH (optionnel):**

1. Ouvrir les **Variables d'environnement système**
2. Ajouter `C:\Users\<username>\redsentinel-cli` au PATH
3. Créer un script `redsentinel.cmd` dans ce répertoire contenant:
```cmd
@echo off
py -3.12 "%~dp0run.py" %*
```

### Module 'rich' introuvable

```powershell
# Réinstaller les dépendances
pip install -r requirements.txt --force-reinstall

# Ou avec Python 3.12 spécifiquement
py -3.12 -m pip install -r requirements.txt --force-reinstall
```

### Plusieurs versions de Python

Si vous avez plusieurs versions de Python (3.11, 3.12, 3.13), utilisez le Python Launcher:

```powershell
# Lister les versions disponibles
py --list

# Utiliser Python 3.12 spécifiquement
py -3.12 run.py

# Installer pour Python 3.12
py -3.12 -m pip install -e .
```

## 📦 Dépendances Système (Outils externes)

Certaines fonctionnalités nécessitent des outils externes:

### Nmap
```powershell
# Télécharger depuis: https://nmap.org/download.html
# Installer et ajouter au PATH
```

### Masscan
```powershell
# Télécharger depuis: https://github.com/robertdavidgraham/masscan
# Compiler ou utiliser les binaires pré-compilés
```

### Autres outils (optionnels)
- **Nikto**: Perl requis
- **Nuclei**: https://github.com/projectdiscovery/nuclei
- **ffuf**: https://github.com/ffuf/ffuf
- **Hydra**: Via Cygwin ou WSL

**Note**: Pour une meilleure expérience avec les outils Linux, utilisez **WSL2** (Windows Subsystem for Linux).

## 🔄 Mise à Jour

```powershell
cd C:\Users\<username>\redsentinel-cli
git pull
pip install -e . --upgrade
```

## 🖥️ WSL (Recommandé pour outils Linux)

Pour utiliser tous les outils de pentesting:

1. Installer WSL2:
```powershell
wsl --install
```

2. Installer Ubuntu dans WSL:
```powershell
wsl --install -d Ubuntu
```

3. Suivre le guide [INSTALL_LINUX.md](INSTALL_LINUX.md) dans WSL

## 🆘 Support

En cas de problème:

1. Vérifier les logs: `%USERPROFILE%\.redsentinel\logs\`
2. Lancer avec verbose: `py -3.12 run.py --verbose`
3. Consulter: [Documentation complète](https://redsentinel.fr)
4. Ouvrir une issue: [GitHub Issues](https://github.com/votre-repo/redsentinel-cli/issues)

---

**RedSentinel v7.0 - MACHINE DE GUERRE CYBER** 🔴

