#!/usr/bin/env bash
# Script de diagnostic pour RedSentinel

# Couleurs ANSI
RED='\033[31m'
BOLD='\033[1m'
RESET='\033[0m'

# Banner RedSentinel ASCII
printf "${RED}${BOLD}"
cat << 'EOF'

                                                               ,╦@Ñ╦,
                                                           ,╔@▓╢╢╢╢╢╢╣@╗,
                                                      ,╓g╬▓╢╢╢╢╢╩╜╙╩▓╢╢╢╢╢▓N╖,
                                              ,╓╓╦@╬▓╢╢╢╢╢╢▓╩╜        ╙╩▓╢╢╢╢╢╢╣▓@g╦╓,,
                                       ╒╬▓╣╢╢╢╢╢╢╢╢╢╢╢▓╩╙`                 ╙╨╬╣╢╢╢╢╢╢╢╢╢╢╢▓▓╗
                                       ╟╢╢╢╣▓▓╩╩╜╙`                              `╙╙╨╩╬▓╣╢╢╢╣
                                       ╟╢╢╢[                                            ]╢╢╢╣
                                       ╟╢╢╢[                                            ]╢╢╢╣
                                       ╟╢╢╢[                                            ]╢╢╢╣
                                       ╟╢╢╢[                                            ]╢╢╢╣
                                       ╟╢╢╢[                                            ]╢╢╢╣
                                       ╟╢╢╢[                                            ]╢╢╢╣
                                       ╟╢╢╢[                                            ]╢╢╢╣
                                       ]╢╢╢▌                                            ▐╢╢╢▌
                                        ╢╢╢╣                                            ▓╢╢╢C
                                        ╟╢╢╢@                                          ╔╢╢╢▓
                                         ▓╢╢╢╕                                        ,╣╢╢╢`
                                          ╣╢╢╢╕                                      ,▓╢╢╢╛
                                           ▓╢╢╢╗                                    ╓╣╢╢╢╛
                                            ╫╢╢╢▓,                                 ╬╢╢╢▓
                                             ╙╣╢╢╢N                              g▓╢╢╢╝
                                               ╚╢╢╢╢N                          g▓╢╢╢▓
                                                 ╨╢╢╢╢@,                    ,@╣╢╢╢▓`
                                                   ╚▓╢╢╢▓╦,              ,╦▓╢╢╢╢╝²
                                                     ╙╬╢╢╢╢▓N,        ,g▓╢╢╢╢▓╜
                                                        ╙╬╢╢╢╢╢@╦,,╥@▓╢╢╢╢▓╜
                                                           "╩▓╢╢╢╢╢╢╢╢╢╩╙
                                                               ╙╩▓╢Ñ╜
██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██████╔╝█████╗  ██║  ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
██║  ██║███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
🔴 CYBERSECURITY | PENTEST | RED TEAM TOOLKIT
========================================
                    Diagnostic
========================================
EOF
printf "${RESET}"
echo ""

echo "[1] Vérification de l'installation..."
echo ""

# Détecter la méthode d'installation
INSTALLED_VIA=""
REDSENTINEL_PATH=""

if command -v redsentinel &> /dev/null; then
    REDSENTINEL_PATH=$(which redsentinel)
    echo "  ✓ Commande 'redsentinel' trouvée: $REDSENTINEL_PATH"
else
    echo "  ✗ Commande 'redsentinel' non trouvée dans PATH"
fi

if command -v pipx &> /dev/null && pipx list 2>/dev/null | grep -q redsentinel; then
    INSTALLED_VIA="pipx"
    echo "  ✓ Installation détectée: pipx"
    pipx list | grep redsentinel
elif python3 -c "import redsentinel" 2>/dev/null && python3 -c "import redsentinel.cli_menu" 2>/dev/null; then
    INSTALLED_VIA="pip"
    echo "  ✓ Installation détectée: pip"
    REDSENTINEL_PATH=$(python3 -c "import redsentinel.cli_menu; print(redsentinel.cli_menu.__file__)" 2>/dev/null)
    echo "    Chemin: $REDSENTINEL_PATH"
elif [ -f "/usr/local/bin/redsentinel" ]; then
    INSTALLED_VIA="install_sh"
    echo "  ✓ Installation détectée: install.sh"
    echo "    Launcher: /usr/local/bin/redsentinel"
else
    echo "  ✗ Aucune installation de RedSentinel détectée"
fi

echo ""
echo "[2] Vérification du code source..."
echo ""

# Trouver le répertoire source
if [ -f "$REDSENTINEL_PATH" ]; then
    if [ -L "$REDSENTINEL_PATH" ]; then
        REAL_PATH=$(readlink -f "$REDSENTINEL_PATH")
        echo "  ✓ Launcher symlink vers: $REAL_PATH"
    fi
fi

if [ "$INSTALLED_VIA" == "pipx" ]; then
    PIPX_VENV=$(pipx list | grep redsentinel | awk '{print $2}')
    echo "  Pour pipx, chercher dans: ~/.local/share/pipx/venvs/redsentinel/"
fi

# Chercher le repo Git
CURRENT_DIR=$(pwd)
if [ -d "$CURRENT_DIR/.git" ]; then
    echo "  ✓ Repo Git trouvé dans: $CURRENT_DIR"
    echo "    Branche: $(git branch --show-current 2>/dev/null || echo 'unknown')"
    echo "    Commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
else
    echo "  ⚠ Pas de repo Git dans le répertoire courant"
fi

echo ""
echo "[3] Test de la vérification de mise à jour..."
echo ""

if command -v redsentinel &> /dev/null; then
    echo "  Lancement: redsentinel --version"
    redsentinel --version 2>/dev/null || echo "    ✗ Erreur lors du lancement"
else
    echo "  ⚠ Impossible de lancer redsentinel"
fi

echo ""
echo "[4] Vérification Git..."
echo ""

if [ -d ".git" ]; then
    echo "  Branche distante:"
    git remote -v 2>/dev/null || echo "    Aucun remote configuré"
    
    echo ""
    echo "  Dernier commit:"
    git log -1 --oneline 2>/dev/null || echo "    Impossible de récupérer"
    
    echo ""
    echo "  Hash local vs distant:"
    git rev-parse HEAD 2>/dev/null && echo "    Local: $(git rev-parse HEAD)"
    git ls-remote origin HEAD 2>/dev/null | head -1 | awk '{print "    Remote: " $1}' || echo "    ⚠ Impossible de contacter origin"
else
    echo "  ⚠ Pas de repo Git"
fi

echo ""
echo "========================================"
echo "Fin du diagnostic"
echo "========================================"
echo ""
echo "Pour résoudre les problèmes:"
echo "  1. Si 'redsentinel' n'est pas dans PATH: bash reinstall.sh"
echo "  2. Si la mise à jour ne marche pas: vérifiez les remotes Git"
echo "  3. Pour réinstaller proprement: bash reinstall.sh"

