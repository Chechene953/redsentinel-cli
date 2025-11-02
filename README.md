# RedSentinel Automation Prototype

Cette archive contient un prototype d'outil d'automatisation pour tâches de reconnaissance et scan,
avec wrappers pour nmap, nuclei, etc. UTILISATION LÉGALE SEULEMENT: n'exécutez ces outils que sur des cibles
pour lesquelles vous avez une autorisation écrite.

## 🚀 Installation Rapide sur Kali Linux

**Sur Kali Linux récent (2024+), vous avez 2 options :**

### Option 1 : Avec pipx (✅ Recommandé sur Kali)

```bash
# Installer pipx si ce n'est pas déjà fait
sudo apt install pipx
pipx ensurepath

# Installer RedSentinel
cd ~/redsentinel-cli-main
pipx install -e .

# Tester
redsentinel --help
```

### Option 2 : Installation globale (force)

```bash
cd ~/redsentinel-cli-main
sudo pip3 install -e . --break-system-packages
redsentinel  # Testez l'installation
```

> 💡 **Pour mettre à jour une version déjà installée** : `bash update.sh`  
> 💡 **Si vous avez déjà essayé d'installer et ça ne marche pas** : `bash reinstall.sh`

---

## Installation sur Kali Linux

⚠️ **Avant de commencer**, assurez-vous d'avoir les outils système suivants installés :
- `python3` et `pip3`
- `nmap` (pour les scans réseau)
- `git` (pour cloner le dépôt)

Sur Kali Linux, ils sont généralement déjà installés. Sinon :
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv nmap git
```

### Méthode 1 : Installation avec pipx ⭐ RECOMMANDÉE

**pipx** est parfait pour installer des applications CLI Python de façon isolée :

```bash
# 1. Installez pipx si ce n'est pas déjà fait
sudo apt install pipx
pipx ensurepath
# Note: Redémarrer le terminal ou faire: source ~/.bashrc

# 2. Clonez ou téléchargez le projet
cd ~
git clone <votre-repo> redsentinel-cli
cd redsentinel-cli

# 3. Installez avec pipx
pipx install -e .
```

**Important:** Avec pipx, `redsentinel` est disponible **partout** sur votre système, dans un environnement isolé !

```bash
# Testez immédiatement
redsentinel --help

# Fonctionne de n'importe quel répertoire
cd ~/Documents
redsentinel recon example.com
```

### Méthode 1b : Installation globale avec pip (alternative)

Si vous préférez une installation globale classique :

```bash
cd ~/redsentinel-cli
sudo pip3 install -e . --break-system-packages
redsentinel --help
```

> **Note:** Sur Kali Linux récent, pipx est généralement préféré. Si vous préférez isoler dans un venv manuel, utilisez la Méthode 2.

### Méthode 3 : Installation avec le script install.sh

```bash
# 1. Clonez ou téléchargez le projet
cd ~
git clone <votre-repo> redsentinel-cli
cd redsentinel-cli

# 2. Lancez le script d'installation
bash install.sh
```

Le script va :
- Créer un environnement virtuel Python dans `~/redsentinel-auto`
- Installer les dépendances
- Créer un launcher global `redsentinel` dans `/usr/local/bin`

**Note:** Le script nécessitera votre mot de passe sudo pour créer le launcher global.

### Méthode 4 : Installation Manuelle

Si vous préférez une installation manuelle sans scripts :

```bash
# 1. Naviguez dans le projet
cd redsentinel-cli

# 2. Créez et activez un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# 3. Installez les dépendances
pip install --upgrade pip
pip install -r requirements.txt

# 4. (Optionnel) Créez un alias dans votre .bashrc ou .zshrc
echo 'alias redsentinel="cd ~/redsentinel-cli && source .venv/bin/activate && python -m redsentinel.cli_menu"' >> ~/.bashrc
source ~/.bashrc
```

### Mise à jour

Si vous avez déjà installé RedSentinel et voulez mettre à jour vers la dernière version :

```bash
cd ~/redsentinel-cli-main  # ou votre répertoire du projet
bash update.sh
```

Le script détecte automatiquement votre méthode d'installation et met à jour proprement.

> **Note :** Si vous utilisez un repo Git privé, le script `update.sh` vous demandera si vous voulez faire un `git pull`. Vous pouvez refuser et utiliser les fichiers locaux que vous avez déjà téléchargés.

**Mise à jour manuelle selon votre méthode :**

```bash
# Si installé via pipx
pipx reinstall redsentinel

# Ou pour forcer la réinstallation complète
pipx uninstall redsentinel
pipx install -e .

# Si installé via pip
cd ~/redsentinel-cli-main
sudo pip3 install -e . --upgrade --break-system-packages

# Si installé via install.sh (réinstallation complète)
bash reinstall.sh
```

### Désinstallation

Pour désinstaller RedSentinel :

**Si installé via pipx :**
```bash
pipx uninstall redsentinel
```

**Si installé via pip :**
```bash
sudo pip3 uninstall redsentinel --break-system-packages
```

**Si installé via install.sh :**
```bash
sudo rm /usr/local/bin/redsentinel
rm -rf ~/redsentinel-auto
```

### Utilisation

Après l'installation, utilisez simplement :

```bash
# Menu interactif
redsentinel

# Ou avec des commandes directes :
redsentinel recon example.com
redsentinel scan example.com --ports 80,443,22
redsentinel nmap example.com
redsentinel webcheck example.com
```

### Configuration

RedSentinel cherche le fichier de configuration `config.yaml` dans l'ordre suivant :
1. Le répertoire courant où vous exécutez la commande
2. `~/.redsentinel/config.yaml` (votre répertoire utilisateur)
3. `/etc/redsentinel/config.yaml` (configuration système)

**Par défaut, le mode `dry_run` est désactivé** dans `config.yaml`. Si vous voulez tester sans exécuter de vraies commandes, modifiez `dry_run: true`.

Vous pouvez copier le fichier `config.yaml` du projet vers l'un de ces emplacements pour personnaliser votre configuration :

```bash
# Configuration utilisateur (recommandé)
mkdir -p ~/.redsentinel
cp config.yaml ~/.redsentinel/config.yaml

# Éditez pour désactiver le mode dry_run si vous voulez exécuter de vraies commandes
nano ~/.redsentinel/config.yaml
# Changez: dry_run: false

# Ou configuration système (nécessite sudo)
sudo mkdir -p /etc/redsentinel
sudo cp config.yaml /etc/redsentinel/config.yaml
```

### Dépannage

#### Erreur "externally-managed-environment"

Sur Kali Linux récent, vous verrez cette erreur si vous utilisez `pip install` sans les bonnes options.

**Solution :**
```bash
# Option 1 : Utilisez pipx (recommandé)
sudo apt install pipx
pipx ensurepath
cd ~/redsentinel-cli-main
pipx install -e .

# Option 2 : Forcez l'installation globale
cd ~/redsentinel-cli-main
sudo pip3 install -e . --break-system-packages
```

#### Erreur "ModuleNotFoundError: No module named 'redsentinel'"

Si vous voyez cette erreur après avoir utilisé `install.sh`, c'est que le package n'a pas été installé correctement.

**Solution :**
```bash
# Nettoyer et réinstaller
sudo rm /usr/local/bin/redsentinel
rm -rf ~/redsentinel-auto
cd ~/redsentinel-cli-main  # ou votre chemin
bash install.sh  # Le script a été mis à jour pour corriger ce problème

# Ou mieux, utilisez pipx
pipx install -e .
```

#### Vérifier l'installation

```bash
# Vérifier que redsentinel est dans le PATH
which redsentinel

# Vérifier que le module Python est trouvé
python3 -c "import redsentinel; print('OK')"

# Tester la commande
redsentinel --help
```

## Structure

- redsentinel/: code source (cli, recon, scanner, webcheck, reporter, utils)
- redsentinel/tools/: wrappers pour outils externes (nmap, nuclei)
- redsentinel/storage/: sqlite wrapper
- plugins/: interface de plugin
- config.yaml: config d'exemple
- requirements.txt

Voir les commentaires dans les fichiers pour plus de détails sur l'utilisation.
