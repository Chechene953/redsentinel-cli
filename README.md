# RedSentinel-CLI - Outil de Sécurité Professionnel

**OUTIL DE SÉCURITÉ / PENTEST - USAGE PROFESSIONNEL UNIQUEMENT**

RedSentinel est une suite complète d'outils d'automatisation pour les tâches de reconnaissance, de scan de sécurité et d'analyse de vulnérabilités, développée par **Redsentinel** (propriétaire : Alexandre Tavares).

> **AVERTISSEMENT IMPORTANT**: N'utilisez RedSentinel QUE sur des cibles pour lesquelles vous avez une autorisation écrite explicite. L'utilisation non autorisée de ces outils peut violer des lois locales et internationales.

## Propriété et Responsabilité

**Propriétaire** : Alexandre Tavares  
**Entreprise** : Redsentinel  
**Logiciel** : RedSentinel v5.0.0  
**Site Internet** : https://redsentinel.fr

### Clause de non-responsabilité

RedSentinel-CLI est fourni "tel quel" et est destiné exclusivement à des fins professionnelles légales. Alexandre Tavares et Redsentinel ne peuvent être tenus responsables de :

- Toute utilisation non autorisée de cet outil
- Toute activité illégale ou malveillante effectuée avec cet outil
- Tout dommage résultant de l'utilisation de cet outil sans autorisation
- Toute violation de lois locales ou internationales liée à l'utilisation de cet outil

L'utilisateur reconnaît être le seul responsable de l'utilisation de RedSentinel et s'engage à l'utiliser uniquement dans le cadre légal et éthique de ses missions professionnelles de sécurité informatique autorisées.

## Documentation

- [SECURITY.md](SECURITY.md) - Politique de sécurité et usage responsable
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Solutions aux problèmes courants

## Installation Rapide sur Kali Linux

### Option 1 : Avec pipx (Recommandé)

```bash
# Installer pipx si nécessaire
sudo apt install pipx
pipx ensurepath

# Installer RedSentinel
cd ~/redsentinel-cli
pipx install -e .

# Tester
redsentinel --help
```

### Option 2 : Installation globale

```bash
cd ~/redsentinel-cli
sudo pip3 install -e . --break-system-packages
redsentinel
```

### Mise à jour

Pour mettre à jour une version déjà installée :

```bash
cd ~/redsentinel-cli
bash update.sh
```

Ou manuellement :
```bash
# Avec pipx
pipx reinstall redsentinel

# Avec pip
sudo pip3 install -e . --upgrade --break-system-packages
```

## Utilisation

```bash
# Menu interactif
redsentinel

# Commandes directes
redsentinel --help
```

## Configuration

RedSentinel cherche le fichier `config.yaml` dans l'ordre suivant :

1. Répertoire courant
2. `~/.redsentinel/config.yaml`
3. `/etc/redsentinel/config.yaml`

Par défaut, le mode `dry_run` est désactivé. Vous pouvez le personnaliser :

```bash
mkdir -p ~/.redsentinel
cp config.yaml ~/.redsentinel/config.yaml
nano ~/.redsentinel/config.yaml
```

## Dépannage

### Erreur "externally-managed-environment"

Utilisez pipx ou forcez l'installation :
```bash
sudo pip3 install -e . --break-system-packages
```

### Erreur "ModuleNotFoundError"

Réinstallez proprement :
```bash
bash reinstall.sh
```

## Structure du Projet

- `redsentinel/` : Code source (CLI, reconnaissance, scan, analyse)
- `redsentinel/tools/` : Wrappers pour outils externes
- `redsentinel/osint/` : Sources OSINT
- `redsentinel/intel/` : Modules d'intelligence
- `redsentinel/attacks/` : Outils d'exploitation
- `redsentinel/api/` : Tests de sécurité API
- `redsentinel/owasp/` : Mapping OWASP Top 10
- `config.yaml` : Configuration par défaut
- `requirements.txt` : Dépendances Python

## Fonctionnalités Principales

- Reconnaissance et énumération (DNS, sous-domaines, certificats)
- Scan de ports et services (Nmap, Masscan)
- Analyse de vulnérabilités (Nuclei, CMS scanners)
- Classification OWASP Top 10 2021 automatique
- Intelligence menaces et corrélation de données
- Tests de sécurité API et applications web
- Gestion de cibles et monitoring continu
- Analyses IA pour découverte automatique

## Licence et Utilisation

RedSentinel est destiné à un usage professionnel exclusivement. Toute utilisation non autorisée est strictement interdite et peut engendrer des poursuites légales.

Contact : Alexandre Tavares / Redsentinel

Site web : https://redsentinel.fr

