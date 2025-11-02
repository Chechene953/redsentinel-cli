#!/usr/bin/env bash
set -euo pipefail

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
                    Installation
========================================
EOF
printf "${RESET}"
echo ""

# Déterminer le répertoire d'origine (où se trouve install.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$HOME/redsentinel-auto"
VENV_DIR="$PROJECT_DIR/.venv"
PYTHON_BIN="$(which python3 2>/dev/null || echo /usr/bin/python3)"
LAUNCHER="/usr/local/bin/redsentinel"

echo "[*] Installing RedSentinel into $PROJECT_DIR"
echo "[*] Source directory: $SCRIPT_DIR"

# Copier tous les fichiers du projet vers le répertoire de destination
mkdir -p "$PROJECT_DIR"
echo "[*] Copying project files..."
cp -r "$SCRIPT_DIR"/* "$PROJECT_DIR/" 2>/dev/null || true

cd "$PROJECT_DIR"

if [ ! -d "$VENV_DIR" ]; then
  echo "[*] Creating virtualenv..."
  $PYTHON_BIN -m venv "$VENV_DIR"
fi

echo "[*] Activating venv and installing requirements..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet

if [ -f requirements.txt ]; then
  pip install -r requirements.txt --quiet
else
  echo "[!] requirements.txt not found in $PROJECT_DIR"
  exit 1
fi

# Installer le package en mode développement
if [ -f setup.py ]; then
  echo "[*] Installing RedSentinel package in development mode..."
  pip install -e . --quiet
fi

if [ ! -f "redsentinel/cli_menu.py" ]; then
  echo "[!] redsentinel/cli_menu.py not found. Add the file and re-run."
  exit 1
fi

echo "[*] Creating launcher $LAUNCHER (sudo required if not root)..."
sudo tee "$LAUNCHER" > /dev/null <<EOF
#!/usr/bin/env bash
PROJECT_DIR="$PROJECT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"
if [ -f "\$VENV_DIR/bin/activate" ]; then
  # shellcheck disable=SC1090
  source "\$VENV_DIR/bin/activate"
fi
python -m redsentinel.cli_menu "\$@"
EOF

sudo chmod +x "$LAUNCHER"

echo "[*] Installation complete."
echo "You can run: redsentinel"
echo "Examples:"
echo "  redsentinel                 # interactive menu"
echo "  redsentinel recon example.com"
echo "  redsentinel scan example.com --ports 80,443,22"