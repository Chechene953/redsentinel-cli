# RedSentinel Automation Prototype

Cette archive contient un prototype d'outil d'automatisation pour tâches de reconnaissance et scan,
avec wrappers pour nmap, nuclei, etc. UTILISATION LÉGALE SEULEMENT: n'exécutez ces outils que sur des cibles
pour lesquelles vous avez une autorisation écrite.

## 🚀 Installation Rapide sur Kali Linux

**La méthode la plus simple :**

```bash
cd ~/redsentinel-cli  # ou le chemin où se trouve le projet
sudo pip3 install -e .
redsentinel  # Testez l'installation
```

C'est tout ! Vous pouvez maintenant utiliser `redsentinel` depuis n'importe où.

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

### Méthode 1 : Installation via setup.py (La plus simple)

```bash
# 1. Clonez ou téléchargez le projet
cd ~
git clone <votre-repo> redsentinel-cli
cd redsentinel-cli

# 2. Installez avec pip (installation globale, nécessite sudo)
sudo pip3 install -e .

# Ou installez dans un environnement virtuel (recommandé)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Après cette installation, vous pourrez utiliser `redsentinel` directement depuis n'importe où.

### Méthode 2 : Installation avec le script install.sh

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

### Méthode 3 : Installation Manuelle

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

### Désinstallation

Pour désinstaller RedSentinel :

**Si installé via pip :**
```bash
sudo pip3 uninstall redsentinel
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

Vous pouvez copier le fichier `config.yaml` du projet vers l'un de ces emplacements pour personnaliser votre configuration :

```bash
# Configuration utilisateur (recommandé)
mkdir -p ~/.redsentinel
cp config.yaml ~/.redsentinel/config.yaml

# Ou configuration système (nécessite sudo)
sudo mkdir -p /etc/redsentinel
sudo cp config.yaml /etc/redsentinel/config.yaml
```

## Structure

- redsentinel/: code source (cli, recon, scanner, webcheck, reporter, utils)
- redsentinel/tools/: wrappers pour outils externes (nmap, nuclei)
- redsentinel/storage/: sqlite wrapper
- plugins/: interface de plugin
- config.yaml: config d'exemple
- requirements.txt

Voir les commentaires dans les fichiers pour plus de détails sur l'utilisation.
