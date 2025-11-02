# Guide d'Installation RedSentinel

## 🚨 Si vous avez déjà essayé d'installer et ça ne marche pas

### Nettoyage et Réinstallation

```bash
# 1. Nettoyer l'ancienne installation
sudo rm /usr/local/bin/redsentinel
rm -rf ~/redsentinel-auto

# 2. Réinstaller proprement
cd ~/redsentinel-cli-main  # ou le chemin de votre projet
bash install.sh
```

## Méthodes d'Installation

### Méthode Recommandée : setup.py (La plus simple)

Cette méthode installe RedSentinel **globalement** sur votre système sans venv :

```bash
cd ~/redsentinel-cli-main
sudo pip3 install -e .
redsentinel  # Testez
```

✅ **Avantage** : Fonctionne partout, pas besoin de venv  
✅ **Avantage** : Simple à désinstaller : `sudo pip3 uninstall redsentinel`

### Méthode Alternative : install.sh

Si vous préférez un environnement isolé :

```bash
cd ~/redsentinel-cli-main
bash install.sh
redsentinel  # Testez
```

Cette méthode crée un venv isolé dans `~/redsentinel-auto` et un launcher global.

## Dépannage

### Erreur "ModuleNotFoundError: No module named 'redsentinel'"

Cela signifie que le package n'est pas installé dans l'environnement Python utilisé.

**Solution :**
```bash
# Option 1 : Réinstaller avec setup.py (recommandé)
cd ~/redsentinel-cli-main
sudo pip3 uninstall redsentinel  # si déjà installé
sudo pip3 install -e .

# Option 2 : Réinstaller avec install.sh (mis à jour)
cd ~/redsentinel-cli-main
rm -rf ~/redsentinel-auto
sudo rm /usr/local/bin/redsentinel
bash install.sh
```

### Vérifier l'installation

```bash
# Vérifier que redsentinel est dans le PATH
which redsentinel

# Vérifier que le module Python est trouvé
python3 -c "import redsentinel; print(redsentinel.__file__)"

# Tester la commande
redsentinel --help
```

## Configuration

Après l'installation, vous pouvez créer une configuration personnalisée :

```bash
mkdir -p ~/.redsentinel
cp config.yaml ~/.redsentinel/config.yaml
# Éditez ~/.redsentinel/config.yaml selon vos besoins
```

## Mise à jour

Si vous avez déjà installé une ancienne version et voulez mettre à jour :

```bash
cd ~/redsentinel-cli-main
bash update.sh
```

Le script `update.sh` détecte automatiquement votre méthode d'installation et met à jour proprement.

**Mise à jour manuelle :**

```bash
# Si installé via pipx
pipx reinstall redsentinel

# Si installé via pip
cd ~/redsentinel-cli-main
sudo pip3 install -e . --upgrade --break-system-packages

# Si installé via install.sh
bash reinstall.sh
```

## Désinstallation

**Si installé via setup.py/pip :**
```bash
sudo pip3 uninstall redsentinel --break-system-packages
```

**Si installé via pipx :**
```bash
pipx uninstall redsentinel
```

**Si installé via install.sh :**
```bash
sudo rm /usr/local/bin/redsentinel
rm -rf ~/redsentinel-auto
```

