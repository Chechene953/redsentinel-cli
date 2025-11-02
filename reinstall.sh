#!/usr/bin/env bash
# Script de réinstallation propre de RedSentinel

set -euo pipefail

echo "========================================"
echo "RedSentinel - Réinstallation Propre"
echo "========================================"
echo ""

# Vérifier qu'on est dans le bon répertoire
if [ ! -f "setup.py" ] || [ ! -d "redsentinel" ]; then
    echo "[!] Erreur : Ce script doit être lancé depuis le répertoire du projet"
    echo "    Répertoire actuel: $(pwd)"
    exit 1
fi

echo "[*] Étape 1: Nettoyage de l'ancienne installation"
echo ""

# Nettoyer l'installation via install.sh
if [ -f "/usr/local/bin/redsentinel" ]; then
    echo "  - Suppression de /usr/local/bin/redsentinel"
    sudo rm /usr/local/bin/redsentinel
fi

if [ -d "$HOME/redsentinel-auto" ]; then
    echo "  - Suppression de ~/redsentinel-auto"
    rm -rf "$HOME/redsentinel-auto"
fi

# Nettoyer l'installation via pip/pipx
if python3 -c "import redsentinel" 2>/dev/null; then
    echo "  - Désinstallation du package pip installé"
    sudo pip3 uninstall redsentinel -y --break-system-packages 2>/dev/null || true
fi

# Nettoyer pipx
if command -v pipx &> /dev/null && pipx list | grep -q redsentinel; then
    echo "  - Désinstallation du package pipx installé"
    pipx uninstall redsentinel 2>/dev/null || true
fi

echo ""
echo "[*] Étape 2: Installation propre"
echo ""

echo "Choisissez votre méthode d'installation :"
echo "  1) pipx (recommandé sur Kali)"
echo "  2) pip global avec --break-system-packages"
echo "  3) Annuler"
read -p "Votre choix [1-3] : " -n 1 -r
echo

if [[ $REPLY =~ ^1$ ]]; then
    echo ""
    echo "  Installation avec pipx..."
    
    if ! command -v pipx &> /dev/null; then
        echo "  pipx n'est pas installé. Installation..."
        sudo apt install pipx
    fi
    
    pipx ensurepath
    pipx install -e .
    
elif [[ $REPLY =~ ^2$ ]]; then
    echo ""
    echo "  Installation avec pip (global)..."
    sudo pip3 install -e . --break-system-packages
    
else
    echo ""
    echo "Installation annulée."
    echo ""
    echo "Si vous préférez installer dans un venv, lancez:"
    echo "  bash install.sh"
    exit 0
fi

echo ""
echo "========================================"
echo "[✓] Installation terminée !"
echo "========================================"
echo ""
echo "Testez avec:"
echo "  redsentinel --help"
echo ""

