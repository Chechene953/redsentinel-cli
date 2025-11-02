#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$HOME/redsentinel-auto"
VENV_DIR="$PROJECT_DIR/.venv"
PYTHON_BIN="/usr/bin/python3"
LAUNCHER="/usr/local/bin/redsentinel"

echo "[*] Installing RedSentinel into $PROJECT_DIR"

mkdir -p "$PROJECT_DIR"
# If running from the zip extracted location, assume files are already there.
cd "$PROJECT_DIR"

if [ ! -d "$VENV_DIR" ]; then
  echo "[*] Creating virtualenv..."
  $PYTHON_BIN -m venv "$VENV_DIR"
fi

echo "[*] Activating venv and installing requirements..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
if [ -f requirements.txt ]; then
  pip install -r requirements.txt
else
  echo "[!] requirements.txt not found in $PROJECT_DIR"
fi

if [ ! -f "redsentinel/cli_menu.py" ]; then
  echo "[!] redsentinel/cli_menu.py not found. Add the file and re-run."
  exit 1
fi

echo "[*] Creating launcher $LAUNCHER (sudo required if not root)..."
sudo tee "$LAUNCHER" > /dev/null <<'EOF'
#!/usr/bin/env bash
PROJECT_DIR="$PROJECT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"
if [ -f "$VENV_DIR/bin/activate" ]; then
  # shellcheck disable=SC1090
  source "$VENV_DIR/bin/activate"
fi
python -m redsentinel.cli_menu "$@"
EOF

sudo chmod +x "$LAUNCHER"

echo "[*] Installation complete."
echo "You can run: redsentinel"
echo "Examples:"
echo "  redsentinel                 # interactive menu"
echo "  redsentinel recon example.com"
echo "  redsentinel scan example.com --ports 80,443,22"
