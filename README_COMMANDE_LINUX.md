# 🐧 Utiliser la commande `redsentinel` sur Linux

## ✅ Installation

```bash
cd /home/alext/redsentinel-cli
sudo bash install.sh
```

## 🚀 Après l'installation

**La commande `redsentinel` est disponible globalement!**

```bash
# Simplement taper
redsentinel
```

## 📋 Comment ça marche?

L'installation crée **DEUX** points d'entrée:

### 1️⃣ Launcher global (`/usr/local/bin/redsentinel`)

```bash
#!/usr/bin/env bash
PROJECT_DIR="~/redsentinel-auto"
VENV_DIR="$PROJECT_DIR/.venv"

# Utilise le script installé par pip
if [ -f "$VENV_DIR/bin/redsentinel" ]; then
  exec "$VENV_DIR/bin/redsentinel" "$@"
else
  # Fallback: Python direct
  source "$VENV_DIR/bin/activate"
  python -m redsentinel "$@"
fi
```

### 2️⃣ Entry point Python (via `setup.py`)

Dans `setup.py`:
```python
entry_points={
    "console_scripts": [
        "redsentinel=redsentinel.cli_menu:main",
    ],
}
```

Crée automatiquement: `~/redsentinel-auto/.venv/bin/redsentinel`

## ✅ Tests

```bash
# Test 1: Vérifier que la commande existe
which redsentinel
# → /usr/local/bin/redsentinel

# Test 2: Version
redsentinel --version
# → RedSentinel v7.0.0

# Test 3: Aide
redsentinel --help

# Test 4: Lancer le menu
redsentinel
# → Menu interactif "MACHINE DE GUERRE CYBER"
```

## 🔧 Test automatique

```bash
# Lancer le script de test
bash test_install.sh
```

Cela vérifie:
- ✅ Python installé
- ✅ Module `redsentinel` importable
- ✅ Commande `redsentinel` dans le PATH
- ✅ Version correcte (7.0.0)
- ✅ Fichiers d'installation présents

## 🎯 Utilisation quotidienne

```bash
# Menu interactif (par défaut)
redsentinel

# Aide
redsentinel --help

# Version
redsentinel --version

# Commandes CLI directes (avec cli_main.py)
redsentinel recon subdomains example.com
redsentinel vuln nuclei https://example.com
redsentinel osint gather example.com
```

## 🔄 Mise à jour

```bash
cd ~/redsentinel-auto
git pull
sudo bash install.sh  # Réinstaller
```

## 🐛 Dépannage

### Problème: "redsentinel: command not found"

**Solution 1**: Vérifier le PATH
```bash
echo $PATH | grep "/usr/local/bin"
```

Si absent, ajouter dans `~/.bashrc`:
```bash
export PATH="/usr/local/bin:$PATH"
source ~/.bashrc
```

**Solution 2**: Utiliser le chemin complet
```bash
/usr/local/bin/redsentinel
```

**Solution 3**: Relancer l'installation
```bash
sudo bash install.sh
```

### Problème: Permission denied

```bash
sudo chmod +x /usr/local/bin/redsentinel
```

### Problème: Module non trouvé

```bash
cd ~/redsentinel-auto
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## 📊 Architecture de l'installation

```
/usr/local/bin/
  └── redsentinel (launcher bash)
       ↓
~/redsentinel-auto/
  ├── .venv/
  │   └── bin/
  │       └── redsentinel (script Python créé par setuptools)
  │            ↓
  ├── redsentinel/
  │   ├── __init__.py
  │   ├── __main__.py (point d'entrée python -m redsentinel)
  │   └── cli_menu.py (fonction main())
  └── setup.py (définit entry_points)

~/.redsentinel/
  ├── config.yaml
  ├── redsentinel.db
  └── logs/
```

## 🎯 Résultat Final

**Une seule commande suffit:**
```bash
redsentinel
```

**Et ça marche de n'importe où dans le système!**

```bash
cd /tmp
redsentinel --version
# → RedSentinel v7.0.0

cd /home/user/Documents
redsentinel
# → Menu interactif

cd ~
redsentinel --help
# → Aide
```

---

## 📚 Fichiers de documentation

- **Installation complète**: `LINUX_INSTALLATION.txt`
- **Guide de démarrage**: `QUICK_START.md`
- **Installation détaillée**: `INSTALL_LINUX.md`
- **Test d'installation**: `test_install.sh`

---

**🔴 RedSentinel v7.0 - MACHINE DE GUERRE CYBER**

La commande `redsentinel` fonctionne maintenant parfaitement sur Linux! 🎉

