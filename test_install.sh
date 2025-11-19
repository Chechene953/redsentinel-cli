#!/usr/bin/env bash
# Script de test pour vérifier l'installation de RedSentinel

echo "========================================"
echo "  Test d'installation RedSentinel v7.0"
echo "========================================"
echo ""

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction de test
test_command() {
    local cmd="$1"
    local description="$2"
    
    echo -n "Testing: $description... "
    if $cmd > /dev/null 2>&1; then
        echo -e "${GREEN}✓ OK${NC}"
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        return 1
    fi
}

# Tests
echo "1. Vérification de Python"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "   ${GREEN}✓${NC} Python trouvé: $PYTHON_VERSION"
else
    echo -e "   ${RED}✗${NC} Python3 non trouvé!"
    exit 1
fi

echo ""
echo "2. Vérification de l'installation RedSentinel"

# Test si la commande existe
if command -v redsentinel &> /dev/null; then
    echo -e "   ${GREEN}✓${NC} Commande 'redsentinel' trouvée dans le PATH"
    REDSENTINEL_PATH=$(which redsentinel)
    echo "     Chemin: $REDSENTINEL_PATH"
else
    echo -e "   ${YELLOW}⚠${NC} Commande 'redsentinel' non trouvée dans le PATH"
    echo "     Vérifiez que /usr/local/bin est dans votre PATH"
fi

echo ""
echo "3. Test de l'import Python"
if python3 -c "from redsentinel import __version__; print(f'Version: {__version__}')" 2>/dev/null; then
    VERSION=$(python3 -c "from redsentinel import __version__; print(__version__)")
    echo -e "   ${GREEN}✓${NC} Module Python importé avec succès"
    echo "     Version détectée: $VERSION"
else
    echo -e "   ${RED}✗${NC} Impossible d'importer le module redsentinel"
    echo "     Lancez: bash install.sh"
fi

echo ""
echo "4. Test de la commande redsentinel"
if command -v redsentinel &> /dev/null; then
    if redsentinel --version 2>&1 | grep -q "RedSentinel"; then
        echo -e "   ${GREEN}✓${NC} Commande redsentinel fonctionne!"
        redsentinel --version
    else
        echo -e "   ${YELLOW}⚠${NC} Commande redsentinel existe mais problème d'exécution"
    fi
else
    echo -e "   ${YELLOW}⚠${NC} Commande redsentinel non disponible"
fi

echo ""
echo "5. Vérification des fichiers d'installation"

FILES_TO_CHECK=(
    "$HOME/redsentinel-auto/.venv"
    "$HOME/redsentinel-auto/redsentinel"
    "/usr/local/bin/redsentinel"
)

for file in "${FILES_TO_CHECK[@]}"; do
    if [ -e "$file" ]; then
        echo -e "   ${GREEN}✓${NC} $file"
    else
        echo -e "   ${RED}✗${NC} $file (manquant)"
    fi
done

echo ""
echo "========================================"
echo "  Résumé"
echo "========================================"

if command -v redsentinel &> /dev/null && redsentinel --version 2>&1 | grep -q "RedSentinel"; then
    echo -e "${GREEN}✓ Installation OK!${NC}"
    echo ""
    echo "Vous pouvez maintenant utiliser:"
    echo "  $ redsentinel"
    echo "  $ redsentinel --help"
    echo "  $ redsentinel --version"
else
    echo -e "${YELLOW}⚠ Installation incomplète${NC}"
    echo ""
    echo "Pour installer RedSentinel:"
    echo "  $ sudo bash install.sh"
    echo ""
    echo "Après l'installation, redémarrez votre terminal ou tapez:"
    echo "  $ source ~/.bashrc"
fi

echo ""

