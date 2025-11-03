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
# Interface en ligne de commande (CLI)
redsentinel

# Interface graphique (GUI)
redsentinel --gui

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

- `redsentinel/` : Code source (CLI, GUI, reconnaissance, scan, analyse)
- `redsentinel/gui/` : Interface graphique moderne (CustomTkinter)
- `redsentinel/cli_menu.py` : Menu interactif CLI
- `redsentinel/tools/` : Wrappers pour outils externes
- `redsentinel/osint/` : Sources OSINT
- `redsentinel/intel/` : Modules d'intelligence
- `redsentinel/attacks/` : Outils d'exploitation
- `redsentinel/api/` : Tests de sécurité API
- `redsentinel/owasp/` : Mapping OWASP Top 10
- `redsentinel/ai/` : Modules IA et automatisation
- `config.yaml` : Configuration par défaut
- `requirements.txt` : Dépendances Python

## Fonctionnalités Principales

**Deux interfaces disponibles :**
- **CLI interactif** : Menu hiérarchique en terminal avec Rich
- **GUI moderne** : Interface graphique intuitive avec CustomTkinter

**Fonctionnalités complètes :**
- **Reconnaissance professionnelle avancée** : Pipeline complet passif+actif (15+ sources OSINT, DNS bruteforce, reverse DNS, historique)
- **Énumération multi-sources** : crt.sh, Certspotter, URLScan, AlienVault, HackerTarget, SecurityTrails
- **Scan de ports** : Profiling de services et bannières automatisés, détection OS, 200 connexions concurrentes
- **Analyse DNS** : Tous enregistrements (A/AAAA/MX/TXT/NS/CNAME/SOA/SRV/PTR/CAA), détection AXFR, vérifications SPF/DMARC
- **Audit SSL/TLS** : Certification, protocoles, vulnérabilités, notes de sécurité (style SSL Labs)
- **Détection technologies** : Serveurs, frameworks, CMS, CDN, WAF
- **Cloud reconnaissance** : S3/GCP/Azure, Cloudflare, historique DNS
- **Analyse de vulnérabilités** : Nuclei, Nikto, scanners CMS, CVE (OWASP Top 10 2021)
- **IA et automatisation** : Découverte, recommandations, chemins d’attaque, corrélations
- **Exploitation** : ffuf, Hydra/Medusa, recherche d’exploits (ExploitDB/MSF)
- **OSINT et TI** : Shodan, Censys, email, GitHub, fuites éventuelles, corrélations
- **Gestion et monitoring** : Cibles, surveillance continue, workflows presets

## Licence et Utilisation

RedSentinel est destiné à un usage professionnel exclusivement. Toute utilisation non autorisée est strictement interdite et peut engendrer des poursuites légales.

Contact : Alexandre Tavares / Redsentinel

Site web : https://redsentinel.fr

