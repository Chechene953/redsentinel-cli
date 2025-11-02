#!/usr/bin/env bash
# Script de mise à jour de RedSentinel

set -euo pipefail

# Banner RedSentinel ASCII
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
                    Mise à jour
========================================
EOF
echo ""

# Vérifier qu'on est dans le bon répertoire
if [ ! -f "setup.py" ] || [ ! -d "redsentinel" ]; then
    echo "[✗] Erreur : Ce script doit être lancé depuis le répertoire du projet"
    echo "    Répertoire actuel: $(pwd)"
    exit 1
fi

echo "[>] Étape 1: Vérification de l'installation actuelle"
echo ""

# Détecter la méthode d'installation
INSTALLED_VIA=""
if command -v pipx &> /dev/null && pipx list 2>/dev/null | grep -q redsentinel; then
    INSTALLED_VIA="pipx"
    CURRENT_VERSION=$(pipx list 2>/dev/null | grep redsentinel | awk '{print $2}' || echo "unknown")
    echo "  ✓ Installation détectée: pipx"
    echo "  Version actuelle: $CURRENT_VERSION"
elif python3 -c "import redsentinel" 2>/dev/null && python3 -c "import redsentinel.cli_menu" 2>/dev/null; then
    INSTALLED_VIA="pip"
    echo "  ✓ Installation détectée: pip"
elif [ -f "/usr/local/bin/redsentinel" ]; then
    INSTALLED_VIA="install_sh"
    echo "  ✓ Installation détectée: install.sh"
else
    echo "  ✗ Aucune installation de RedSentinel détectée"
    echo ""
    echo "Installez d'abord RedSentinel avec:"
    echo "  bash reinstall.sh"
    exit 1
fi

echo ""
echo "[>] Étape 2: Mise à jour des fichiers sources"
echo ""

# Si c'est un git repo, faire un pull
if [ -d ".git" ]; then
    echo "  Repository Git détecté (public ou privé)"
    read -p "Voulez-vous faire un 'git pull' pour mettre à jour les sources? [O/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Oo]$ ]] || [[ -z $REPLY ]]; then
        git pull || echo "  [⚠] git pull a échoué. Continuez avec les fichiers locaux actuels."
        echo ""
    fi
else
    echo "  Repository Git non détecté"
    echo "  ✓ Utilisation des fichiers sources locaux actuels"
fi

echo ""
echo "[>] Étape 3: Réinstallation avec la même méthode"
echo ""

case $INSTALLED_VIA in
    pipx)
        echo "  Mise à jour via pipx..."
        pipx reinstall redsentinel 2>/dev/null || {
            echo "  pipx reinstall a échoué, désinstallation/réinstallation..."
            pipx uninstall redsentinel
            pipx install -e .
        }
        ;;
    
    pip)
        echo "  Mise à jour via pip..."
        sudo pip3 install -e . --upgrade --break-system-packages
        ;;
    
    install_sh)
        echo "  Mise à jour via install.sh..."
        echo "  Désinstallation de l'ancienne version..."
        sudo rm -f /usr/local/bin/redsentinel
        rm -rf "$HOME/redsentinel-auto"
        
        echo "  Réinstallation..."
        bash install.sh
        ;;
esac

echo ""
echo "========================================"
echo "[✓] Mise à jour terminée !"
echo "========================================"
echo ""
echo "Testez avec:"
echo "  redsentinel"
echo ""
echo "Si vous rencontrez des problèmes, lancez:"
echo "  bash reinstall.sh"
echo ""

