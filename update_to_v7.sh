#!/usr/bin/env bash
set -euo pipefail

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${RED}${BOLD}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   RedSentinel v7.0 - MACHINE DE GUERRE CYBER             ║
║   Mise à jour vers le nouveau CLI                        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

PROJECT_DIR="$HOME/redsentinel-auto"
VENV_DIR="$PROJECT_DIR/.venv"

echo -e "${BLUE}[*]${NC} Mise à jour de RedSentinel vers v7.0..."
echo ""

# Vérifier si l'installation existe
if [ ! -d "$PROJECT_DIR" ]; then
    echo -e "${RED}[!]${NC} Installation non trouvée dans $PROJECT_DIR"
    echo -e "${YELLOW}[i]${NC} Lancez d'abord: sudo bash install.sh"
    exit 1
fi

cd "$PROJECT_DIR"

# Sauvegarder la configuration
echo -e "${BLUE}[*]${NC} Sauvegarde de la configuration..."
if [ -f "$HOME/.redsentinel/config.yaml" ]; then
    cp "$HOME/.redsentinel/config.yaml" "$HOME/.redsentinel/config.yaml.backup"
    echo -e "${GREEN}[✓]${NC} Configuration sauvegardée"
fi

# Mettre à jour le dépôt
echo -e "${BLUE}[*]${NC} Récupération des dernières modifications..."
if [ -d ".git" ]; then
    git pull
    echo -e "${GREEN}[✓]${NC} Code mis à jour"
else
    echo -e "${YELLOW}[!]${NC} Pas un dépôt Git, mise à jour manuelle nécessaire"
fi

# Activer le virtualenv
echo -e "${BLUE}[*]${NC} Activation de l'environnement virtuel..."
if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
    echo -e "${GREEN}[✓]${NC} Environnement activé"
else
    echo -e "${RED}[!]${NC} Virtualenv non trouvé, création..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
fi

# Mettre à jour pip
echo -e "${BLUE}[*]${NC} Mise à jour de pip..."
pip install --upgrade pip --quiet

# Réinstaller les dépendances
echo -e "${BLUE}[*]${NC} Mise à jour des dépendances..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --upgrade --quiet
    echo -e "${GREEN}[✓]${NC} Dépendances mises à jour"
fi

# Réinstaller RedSentinel
echo -e "${BLUE}[*]${NC} Réinstallation de RedSentinel..."
pip uninstall redsentinel -y --quiet 2>/dev/null || true
pip install -e . --quiet
echo -e "${GREEN}[✓]${NC} RedSentinel réinstallé"

# Recréer le launcher
echo -e "${BLUE}[*]${NC} Mise à jour du launcher global..."
LAUNCHER="/usr/local/bin/redsentinel"
sudo tee "$LAUNCHER" > /dev/null <<EOF
#!/usr/bin/env bash
PROJECT_DIR="$PROJECT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"

# Utiliser le script installé par setuptools si disponible
if [ -f "\$VENV_DIR/bin/redsentinel" ]; then
  exec "\$VENV_DIR/bin/redsentinel" "\$@"
else
  # Fallback: activer le venv et utiliser Python directement
  if [ -f "\$VENV_DIR/bin/activate" ]; then
    source "\$VENV_DIR/bin/activate"
  fi
  python -m redsentinel "\$@"
fi
EOF

sudo chmod +x "$LAUNCHER"
echo -e "${GREEN}[✓]${NC} Launcher mis à jour"

# Créer le launcher pour le menu interactif
echo -e "${BLUE}[*]${NC} Création du launcher pour le menu interactif..."
MENU_LAUNCHER="/usr/local/bin/redsentinel-menu"
sudo tee "$MENU_LAUNCHER" > /dev/null <<EOF
#!/usr/bin/env bash
PROJECT_DIR="$PROJECT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"

if [ -f "\$VENV_DIR/bin/redsentinel-menu" ]; then
  exec "\$VENV_DIR/bin/redsentinel-menu" "\$@"
else
  if [ -f "\$VENV_DIR/bin/activate" ]; then
    source "\$VENV_DIR/bin/activate"
  fi
  python -c "from redsentinel.cli_menu import interactive_menu; interactive_menu()"
fi
EOF

sudo chmod +x "$MENU_LAUNCHER"
echo -e "${GREEN}[✓]${NC} Launcher menu créé"

echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  ✓ Mise à jour terminée avec succès!                 ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Vérifier la version
echo -e "${BLUE}[*]${NC} Vérification de la version..."
VERSION=$(redsentinel --version 2>&1 | head -n1 || echo "Erreur")
echo -e "    ${BOLD}$VERSION${NC}"
echo ""

echo -e "${YELLOW}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  Nouvelles fonctionnalités disponibles!              ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BOLD}Nouveau CLI avec commandes directes:${NC}"
echo ""
echo -e "  ${GREEN}redsentinel --help${NC}                    # Aide complète"
echo -e "  ${GREEN}redsentinel recon subdomains example.com${NC}  # Reconnaissance"
echo -e "  ${GREEN}redsentinel vuln nuclei https://example.com${NC}  # Scan vulnérabilités"
echo -e "  ${GREEN}redsentinel osint gather example.com${NC}  # OSINT"
echo -e "  ${GREEN}redsentinel report generate scan.json${NC}  # Rapports"
echo ""
echo -e "${BOLD}Menu interactif (ancien style):${NC}"
echo ""
echo -e "  ${GREEN}redsentinel${NC}        # Lance le menu si aucun argument"
echo -e "  ${GREEN}redsentinel-menu${NC}   # Force le menu interactif"
echo ""
echo -e "${BOLD}Interfaces avancées:${NC}"
echo ""
echo -e "  ${GREEN}redsentinel tui${NC}    # Interface TUI moderne"
echo -e "  ${GREEN}redsentinel gui${NC}    # Interface graphique"
echo ""

echo -e "${BLUE}📚 Documentation complète: ${NC}${BOLD}NOUVELLE_CLI_V7.md${NC}"
echo -e "${BLUE}🚀 Guide rapide: ${NC}${BOLD}QUICK_START.md${NC}"
echo ""

echo -e "${YELLOW}Testez maintenant:${NC} ${GREEN}${BOLD}redsentinel --help${NC}"
echo ""

