# 🎨 RedSentinel CLI - Design Guide Complet

> **Guide de design pour créer un CLI Python ultra-stylé pour la reconnaissance et les pentests**

---

## 🎯 Philosophie du Design

- **Style** : Cyberpunk, agressif, professionnel, intimidant
- **Couleurs** : Rouge cyber sur fond noir profond
- **Éthique** : Élégance brutale, efficacité maximale, feedback visuel immédiat
- **Inspiration** : Terminals de hackers dans les films, outils professionnels comme Metasploit, Burp Suite

---

## 🎨 Palette de Couleurs

### Couleurs Principales (ANSI/TrueColor)

```python
# Rouge Cyber RedSentinel
RED_PRIMARY = "#E11D47"        # Rouge principal (HSL: 356 93% 49%)
RED_GLOW = "#FF1A4D"           # Rouge lumineux pour effets glow
RED_DARK = "#CC0000"           # Rouge sombre pour contrastes
RED_BRIGHT = "#FF3366"         # Rouge brillant pour alertes

# Noirs & Gris
BLACK_DEEP = "#0A0A0A"         # Noir profond (background)
ANTHRACITE = "#1A1A1D"         # Anthracite (cards, borders)
GRAY_DARK = "#27272A"          # Gris foncé
GRAY_MEDIUM = "#3F3F46"        # Gris moyen
GRAY_LIGHT = "#71717A"         # Gris clair

# Accents
CYBER_CYAN = "#06B6D4"         # Cyan cyber pour infos techniques
CYBER_GREEN = "#10B981"        # Vert pour succès
CYBER_YELLOW = "#F59E0B"       # Jaune pour warnings
CYBER_ORANGE = "#F97316"       # Orange pour attention

# Blancs
WHITE_PURE = "#FFFFFF"          # Blanc pur
WHITE_SOFT = "#E4E4E7"         # Blanc doux pour textes
```

### Codes ANSI (Fallback pour terminaux basiques)

```python
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_ITALIC = "\033[3m"

# Couleurs
ANSI_RED = "\033[31m"
ANSI_RED_BRIGHT = "\033[91m"
ANSI_GREEN = "\033[32m"
ANSI_GREEN_BRIGHT = "\033[92m"
ANSI_YELLOW = "\033[33m"
ANSI_YELLOW_BRIGHT = "\033[93m"
ANSI_BLUE = "\033[34m"
ANSI_CYAN = "\033[36m"
ANSI_CYAN_BRIGHT = "\033[96m"
ANSI_WHITE = "\033[37m"
ANSI_GRAY = "\033[90m"

# Backgrounds
ANSI_BG_RED = "\033[41m"
ANSI_BG_BLACK = "\033[40m"
ANSI_BG_DARK_GRAY = "\033[100m"
```

---

## 🎭 Banner ASCII Art

### Banner Principal (Démarrage)

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗║
║   ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝║
║   ██████╔╝█████╗  ██║  ██║███████╗█████╗  ██╔██╗ ██║   ██║   ║
║   ██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ║
║   ██║  ██║███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ║
║   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ║
║                                                               ║
║        🔴 CYBERSECURITY | PENTEST | RED TEAM TOOLKIT          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

### Banner Compact (Sous-menus)

```
┌─────────────────────────────────────────────────────────────┐
│  REDSENTINEL > RECON MODULE                                  │
└─────────────────────────────────────────────────────────────┘
```

### Banner Minimaliste (Actions rapides)

```
🔴 REDSENTINEL ────────────────────────────────────────────────
```

---

## 💬 Styles de Messages

### Succès ✅

```
[+] Success message
[✓] Operation completed
[SUCCESS] Task finished successfully
```

**Style** : Vert brillant, bold, avec icône ✓

```python
def success(msg: str):
    return f"{ANSI_GREEN_BRIGHT}{ANSI_BOLD}[✓]{ANSI_RESET} {ANSI_GREEN}{msg}{ANSI_RESET}"
```

### Erreur ❌

```
[!] Error message
[✗] Operation failed
[ERROR] Critical failure detected
```

**Style** : Rouge brillant, bold, avec icône ✗

```python
def error(msg: str):
    return f"{ANSI_RED_BRIGHT}{ANSI_BOLD}[✗]{ANSI_RESET} {ANSI_RED}{msg}{ANSI_RESET}"
```

### Warning ⚠️

```
[!] Warning message
[WARN] Potential issue detected
```

**Style** : Jaune brillant, bold

```python
def warning(msg: str):
    return f"{ANSI_YELLOW_BRIGHT}{ANSI_BOLD}[!]{ANSI_RESET} {ANSI_YELLOW}{msg}{ANSI_RESET}"
```

### Information ℹ️

```
[>] Information message
[INFO] Additional details
[*] Generic info
```

**Style** : Cyan brillant

```python
def info(msg: str):
    return f"{ANSI_CYAN_BRIGHT}{ANSI_BOLD}[>]{ANSI_RESET} {ANSI_CYAN}{msg}{ANSI_RESET}"
```

### Debug 🔍

```
[DEBUG] Debug information
[DBG] Verbose output
```

**Style** : Gris, italic

```python
def debug(msg: str):
    return f"{ANSI_GRAY}{ANSI_ITALIC}[DEBUG]{ANSI_RESET} {ANSI_DIM}{msg}{ANSI_RESET}"
```

---

## 📊 Formats de Sortie

### Tableaux Stylés

```
┌──────────────┬─────────────┬──────────────┬──────────────────┐
│ Host         │ Port        │ Service      │ Status           │
├──────────────┼─────────────┼──────────────┼──────────────────┤
│ 192.168.1.1  │ 80          │ HTTP         │ ✓ OPEN           │
│ 192.168.1.1  │ 443         │ HTTPS        │ ✓ OPEN           │
│ 192.168.1.1  │ 22          │ SSH          │ ✗ FILTERED       │
└──────────────┴─────────────┴──────────────┴──────────────────┘
```

**Code Python** (avec `rich` ou `tabulate`):

```python
from rich.console import Console
from rich.table import Table

console = Console()
table = Table(show_header=True, header_style="bold red")
table.add_column("Host", style="cyan")
table.add_column("Port", style="yellow")
table.add_column("Service", style="green")
table.add_column("Status", style="red")
```

### Progress Bars Animées

```
[████████████████░░░░░░░░] 60% | Scanning ports...
[████████████████████████] 100% | Complete!
```

**Avec `rich`:**

```python
from rich.progress import Progress, BarColumn, Percentage

with Progress(
    "[progress.description]{task.description}",
    BarColumn(bar_width=40),
    Percentage(),
) as progress:
    task = progress.add_task("Scanning...", total=100)
```

### Spinners Animés

```
[⠋] Analyzing...
[⠙] Processing data...
[⠹] Establishing connection...
```

**Options**: `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` (cycle)

---

## 🎬 Animations & Effets

### Typing Effect (pour les banners)

```python
import time
import sys

def typewriter(text: str, delay: float = 0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()
```

### Glow Effect (pour texte important)

```python
def glow_text(text: str, color: str = RED_PRIMARY):
    # Utiliser des caractères spéciaux pour effet glow
    return f"\033]8;;{color}\033\\{text}\033]8;;\033\\"
```

### Pulsation (pour statuts actifs)

```python
import itertools

pulse_chars = ["●", "○"]
for char in itertools.cycle(pulse_chars):
    print(f"\r{char} Scanning...", end="")
    time.sleep(0.5)
```

---

## 📋 Exemples de Sorties Complètes

### Scan de Ports

```
🔴 REDSENTINEL ────────────────────────────────────────────────

[>] Target: example.com
[>] Port Range: 1-1000
[>] Threads: 50

[⠋] Starting port scan...
[✓] Port 80/tcp   OPEN    HTTP        Apache/2.4.41
[✓] Port 443/tcp  OPEN    HTTPS       Apache/2.4.41
[✗] Port 22/tcp   FILTERED SSH         No response
[!] Port 8080/tcp OPEN    HTTP-PROXY  Unusual service

┌─────────┬──────────┬─────────┬──────────────────────┐
│ Port    │ Status   │ Service │ Banner               │
├─────────┼──────────┼─────────┼──────────────────────┤
│ 80      │ ✓ OPEN   │ HTTP    │ Apache/2.4.41        │
│ 443     │ ✓ OPEN   │ HTTPS   │ Apache/2.4.41       │
│ 8080    │ ✓ OPEN   │ PROXY   │ Squid/4.10          │
└─────────┴──────────┴─────────┴──────────────────────┘

[✓] Scan completed: 3 ports open, 997 filtered
[>] Duration: 12.3s
```

### Subdomain Enumeration

```
┌─────────────────────────────────────────────────────────────┐
│  REDSENTINEL > SUBDOMAIN ENUMERATION                        │
└─────────────────────────────────────────────────────────────┘

[>] Target: example.com
[>] Wordlist: /usr/share/wordlists/subdomains.txt (10k entries)
[>] Engines: [passive, active, dns, certificate]

[⠋] Starting enumeration...
[>] Passive: Querying certificate transparency logs...
[✓] Found: api.example.com
[✓] Found: admin.example.com
[✓] Found: dev.example.com
[>] Active: Bruteforcing subdomains...
[✓] Found: mail.example.com
[✓] Found: ftp.example.com

[████████████████░░░░░░] 60% | 6000/10000 tested

Results:
  • api.example.com (200 OK)
  • admin.example.com (403 Forbidden)
  • dev.example.com (200 OK)
  • mail.example.com (301 Redirect)
  • ftp.example.com (220 FTP Ready)

[✓] Enumeration completed: 5 subdomains found
[>] Duration: 45.2s
[>] Output saved to: results/subdomains_example.com.txt
```

### Vulnerability Scan

```
🔴 REDSENTINEL > VULNERABILITY SCAN ─────────────────────────

[>] Target: https://example.com
[>] Profile: OWASP Top 10

[⠋] Initializing scan...
[✓] Target is reachable
[>] Detected: Apache/2.4.41, PHP/7.4.3
[>] Testing 150+ attack vectors...

[!] HIGH: SQL Injection detected in /api/users?id=
    Payload: ' OR '1'='1
    Response: 200 OK (Database error visible)
    CVSS: 9.8 (Critical)

[!] MEDIUM: XSS (Reflected) in /search?q=
    Payload: <script>alert('XSS')</script>
    Response: Payload reflected without encoding
    CVSS: 6.1 (Medium)

[✓] LOW: Missing security headers
    Issues: X-Frame-Options, Content-Security-Policy

┌──────────────────────────────────────────────────────────────┐
│ Summary                                                        │
├──────────────────────────────────────────────────────────────┤
│ Critical: 0                                                    │
│ High:      1                                                    │
│ Medium:    1                                                    │
│ Low:       3                                                    │
│ Info:      12                                                   │
└──────────────────────────────────────────────────────────────┘

[✓] Scan completed
[>] Report: reports/example.com_2025-01-XX.html
```

---

## 🎨 Prompt & Interface

### Prompt Principal

```python
def get_prompt():
    return f"{RED_BRIGHT}{BOLD}redsentinel>{RESET} "
```

### Menu Interactif

```
┌─────────────────────────────────────────────────────────────┐
│                    REDSENTINEL MENU                          │
├─────────────────────────────────────────────────────────────┤
│  [1] Port Scanner                                            │
│  [2] Subdomain Enumeration                                   │
│  [3] Web Vulnerability Scanner                               │
│  [4] DNS Reconnaissance                                      │
│  [5] Cloud Infrastructure Scan                              │
│  [6] Active Directory Enumeration                            │
│  [7] Report Generator                                        │
│  [8] Settings                                                │
│  [0] Exit                                                    │
└─────────────────────────────────────────────────────────────┘

redsentinel> 
```

### Command Help

```
Usage: redsentinel [COMMAND] [OPTIONS]

Commands:
  scan       Perform port scanning
  enum       Subdomain enumeration
  vuln       Vulnerability scanning
  recon      Comprehensive reconnaissance
  report     Generate reports

Options:
  -t, --target     Target host/domain (required)
  -p, --ports      Port range (default: 1-1000)
  -T, --threads    Number of threads (default: 50)
  -o, --output     Output file/directory
  -v, --verbose    Verbose output
  --json           JSON output format

Examples:
  $ redsentinel scan -t example.com -p 1-65535
  $ redsentinel enum -t example.com -w wordlist.txt
  $ redsentinel vuln -t https://example.com --profile owasp
```

---

## 🔤 Typographie

### Fonts Recommandées (pour README/docs)

- **Titres** : `Orbitron`, `Rajdhani` (futuriste, bold)
- **Code** : `Fira Code`, `JetBrains Mono` (monospace, ligatures)
- **Body** : `Inter`, `Roboto` (lisible, moderne)

### Poids de Police

- **Banners/Headers** : Bold (700)
- **Emphase** : Semi-Bold (600)
- **Normal** : Regular (400)
- **Debug/Verbose** : Light (300)

---

## 🎯 Guidelines d'Utilisation

### 1. Toujours afficher le banner au démarrage
### 2. Utiliser des couleurs cohérentes :
   - Rouge = Actions, erreurs, alerts
   - Vert = Succès, ouvertures
   - Jaune = Warnings, attention
   - Cyan = Informations techniques
   - Gris = Debug, verbose

### 3. Feedback visuel immédiat :
   - Progress bars pour opérations longues
   - Spinners pour processus actifs
   - Messages clairs (succès/erreur)

### 4. Formats de sortie :
   - Tableaux pour données structurées
   - Liste à puces pour résultats multiples
   - JSON optionnel pour intégration

### 5. Performance visible :
   - Afficher le temps d'exécution
   - Nombre d'éléments traités
   - Statistiques finales

---

## 🛠️ Bibliothèques Python Recommandées

```python
# Colors & Formatting
rich          # Tables, progress bars, colors, panels
colorama      # Cross-platform ANSI colors
termcolor     # Simple terminal colors

# CLI Framework
click         # Command-line interface creation
argparse      # Built-in argument parsing
typer         # Modern CLI with type hints

# Tables & Output
tabulate      # Simple table formatting
prettytable   # Advanced table formatting

# Animations
alive-progress # Progress bars with animations
tqdm          # Simple progress bars
```

### Exemple d'import minimal

```python
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, SpinnerColumn
from rich.panel import Panel
from rich.text import Text
import click
```

---

## 🎨 Exemple de Code Complet

```python
#!/usr/bin/env python3
"""
RedSentinel CLI - Exemple d'implémentation stylée
"""

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
import click
import time

console = Console()

# Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║   ██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗║
║   ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝║
║   ██████╔╝█████╗  ██║  ██║███████╗█████╗  ██╔██╗ ██║   ██║   ║
║   ██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ║
║   ██║  ██║███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ║
║   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ║
║                                                               ║
║        🔴 CYBERSECURITY | PENTEST | RED TEAM TOOLKIT          ║
╚═══════════════════════════════════════════════════════════════╝
"""

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """RedSentinel - Cybersecurity Toolkit"""
    console.print(BANNER, style="bold red")
    console.print()

@cli.command()
@click.option("-t", "--target", required=True, help="Target host")
@click.option("-p", "--ports", default="1-1000", help="Port range")
@click.option("-T", "--threads", default=50, help="Number of threads")
def scan(target: str, ports: str, threads: int):
    """Perform port scanning"""
    
    console.print(f"[bold cyan][>][/bold cyan] Target: [yellow]{target}[/yellow]")
    console.print(f"[bold cyan][>][/bold cyan] Port Range: [yellow]{ports}[/yellow]")
    console.print(f"[bold cyan][>][/bold cyan] Threads: [yellow]{threads}[/yellow]")
    console.print()
    
    # Progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=100)
        
        # Simulate scanning
        for i in range(100):
            time.sleep(0.02)
            progress.update(task, advance=1)
    
    # Results table
    table = Table(show_header=True, header_style="bold red")
    table.add_column("Port", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Banner", style="white")
    
    table.add_row("80", "[green]✓ OPEN[/green]", "HTTP", "Apache/2.4.41")
    table.add_row("443", "[green]✓ OPEN[/green]", "HTTPS", "Apache/2.4.41")
    table.add_row("22", "[red]✗ FILTERED[/red]", "SSH", "No response")
    
    console.print()
    console.print(table)
    console.print()
    console.print("[bold green][✓][/bold green] Scan completed")

if __name__ == "__main__":
    cli()
```

---

## 📝 Checklist de Design

- [ ] Banner ASCII au démarrage
- [ ] Couleurs cohérentes (rouge cyber sur noir)
- [ ] Progress bars pour opérations longues
- [ ] Messages avec préfixes clairs ([✓], [✗], [!], [>])
- [ ] Tableaux pour données structurées
- [ ] Spinners pour processus actifs
- [ ] Statistiques finales (durée, résultats)
- [ ] Support JSON optionnel
- [ ] Help system intégré
- [ ] Gestion d'erreurs élégante

---

## 🚀 Inspiration

- **Metasploit** : Interface CLI professionnelle
- **Burp Suite** : Feedback visuel clair
- **Nmap** : Output structuré et coloré
- **Masscan** : Rapidité et efficacité
- **The Matrix** : Esthétique cyberpunk

---

**Version**: 1.0  
**Date**: 2025-01  
**Auteur**: RedSentinel Team

---

*"Fast. Clean. Efficient. Everything you need to dominate pentests."*

