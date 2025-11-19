# Guide de Démarrage Rapide - RedSentinel v7.0

## Installation

### Prérequis
- Python 3.10 ou supérieur
- pip ou pipx
- Git

### Installation Standard
```bash
# Cloner le repository
git clone https://github.com/redsentinel/redsentinel-cli.git
cd redsentinel-cli

# Installer les dépendances
pip3 install -r requirements.txt

# Installer RedSentinel
pip3 install -e .

# Vérifier l'installation
redsentinel --version
```

### Installation avec pipx (Recommandé)
```bash
pipx install -e .
pipx ensurepath
source ~/.bashrc
redsentinel --version
```

---

## Configuration

### Configuration de base
```bash
# Copier le template
cp config.yaml.example ~/.redsentinel/config.yaml

# Éditer la configuration
nano ~/.redsentinel/config.yaml
```

### Configuration PostgreSQL (Production)
```yaml
database:
  type: postgresql
  postgresql:
    host: localhost
    port: 5432
    database: redsentinel
    user: redsentinel
    password: your_password
```

### Configuration API Keys (OSINT)
```yaml
osint:
  sources:
    shodan:
      api_key: "your_shodan_key"
    github:
      token: "your_github_token"
    hunter_io:
      api_key: "your_hunter_key"
```

---

## Utilisation de Base

### Interface CLI
```bash
# Lancer l'interface interactive
redsentinel

# Lancer un scan
redsentinel scan --target https://example.com

# Voir les résultats
redsentinel results --scan-id SCAN_ID
```

### Reconnaissance OSINT
```python
#!/usr/bin/env python3
import asyncio
from redsentinel.osint.recon_orchestrator import comprehensive_recon

async def main():
    results = await comprehensive_recon('example.com')
    print(f"Subdomains: {len(results['passive_recon']['sources']['subdomains']['data'])}")
    print(f"Emails: {results['passive_recon']['sources']['emails']['data']['total_found']}")

asyncio.run(main())
```

### Tests OWASP Top 10
```python
#!/usr/bin/env python3
import asyncio
from redsentinel.tests.owasp_top10_automated import OWASPTop10Tester

async def main():
    tester = OWASPTop10Tester()
    results = await tester.test_comprehensive('http://testphp.vulnweb.com')
    
    print(f"Total: {results['total_findings']}")
    print(f"Critical: {results['by_severity']['critical']}")
    print(f"High: {results['by_severity']['high']}")

asyncio.run(main())
```

### Proxy Intercepting
```python
#!/usr/bin/env python3
import asyncio
from redsentinel.proxy.intercepting_proxy import InterceptingProxy

async def main():
    proxy = InterceptingProxy(port=8080)
    print("Proxy lancé sur http://127.0.0.1:8080")
    await proxy.start()

asyncio.run(main())
```

### Génération de Rapports
```python
#!/usr/bin/env python3
import asyncio
from redsentinel.reporting.advanced_reporter import AdvancedReportGenerator, ReportConfig
from pathlib import Path

async def main():
    config = ReportConfig(
        format='pdf',
        template='professional',
        include_compliance=True,
        compliance_frameworks=['OWASP-ASVS', 'PCI-DSS']
    )
    
    generator = AdvancedReportGenerator(config)
    
    # scan_results doit contenir vos résultats
    await generator.generate_report(scan_results, Path('report.pdf'))

asyncio.run(main())
```

---

## Fonctionnalités Avancées

### Post-Exploitation
```python
from redsentinel.exploitation.post_exploitation import PostExploitationOrchestrator

orchestrator = PostExploitationOrchestrator(config)
results = await orchestrator.run_comprehensive_post_exploit(
    target="192.168.1.100",
    session=ssh_session,
    os_type='linux'
)
```

### Machine Learning
```python
from redsentinel.intelligence.ml_analyzer import MLAnalyzer

analyzer = MLAnalyzer()
results = await analyzer.analyze_scan_results(vulnerabilities, responses)

print(f"Filtered vulns: {len(results['filtered_vulnerabilities'])}")
print(f"Anomalies: {len(results['anomalies'])}")
```

### Evasion WAF/IDS
```python
from redsentinel.stealth.evasion import StealthEngine, EvasionProfile

profile = EvasionProfile(
    user_agent_rotation=True,
    payload_encoding='url',
    tor_enabled=True
)

engine = StealthEngine(profile)
request = await engine.prepare_request('GET', url, payload="' OR '1'='1")
```

### Intégrations Externes
```python
from redsentinel.integrations.external_tools import IntegrationManager

manager = IntegrationManager(config)

# OWASP ZAP
zap = manager.get_integration('zap')
scan_id = await zap.start_scan('https://target.com')

# Nmap
nmap = manager.get_integration('nmap')
results = await nmap.scan('192.168.1.0/24', scan_type='full')
```

---

## TUI Advanced

### Lancement
```bash
python -m redsentinel.ui.tui_advanced
```

### Raccourcis Clavier
- `q` - Quitter
- `s` - Nouveau scan
- `r` - Voir résultats
- `p` - Proxy
- `o` - OSINT
- `Ctrl+D` - Toggle Dark Mode
- `Ctrl+Q` - Quitter

---

## API REST

### Lancement du serveur
```bash
uvicorn redsentinel.core.api_server:app --reload
```

### Endpoints disponibles
- `GET /` - Informations API
- `GET /health` - Status santé
- `POST /api/v1/scans` - Créer scan
- `GET /api/v1/scans/{scan_id}` - Détails scan
- `GET /api/v1/vulnerabilities` - Liste vulnérabilités
- `GET /api/v1/reports` - Liste rapports

### Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## Troubleshooting

### redsentinel: command not found
```bash
pipx ensurepath
source ~/.bashrc
```

### Erreur d'installation
```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt --force-reinstall
```

### Problème de database
```bash
# Réinitialiser
rm ~/.redsentinel/data/redsentinel.db
alembic upgrade head
```

### Logs
```bash
# Voir les logs
tail -f ~/.redsentinel/logs/redsentinel.log

# Augmenter verbosité
redsentinel --verbose scan --target example.com
```

---

## Configuration Avancée

### PostgreSQL Setup
```bash
# Installation
sudo apt install postgresql postgresql-contrib

# Création database
sudo -u postgres psql
CREATE DATABASE redsentinel;
CREATE USER redsentinel WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE redsentinel TO redsentinel;
```

### Redis + Celery (Distributed Tasks)
```bash
# Installation
sudo apt install redis-server

# Démarrage worker
celery -A redsentinel.core.distributed_queue worker --loglevel=info
```

### Tor (Anonymisation)
```bash
# Installation
sudo apt install tor

# Démarrage
sudo systemctl start tor

# Configuration dans config.yaml
stealth:
  tor_enabled: true
```

---

## Exemples de Workflows

### Audit Complet
```bash
# 1. OSINT
redsentinel osint --target example.com --all

# 2. Port Scan
redsentinel portscan --target example.com

# 3. Web Scan
redsentinel webscan --target https://example.com

# 4. OWASP Tests
redsentinel owasp --target https://example.com

# 5. Génération Rapport
redsentinel report --scan-id SCAN_ID --format pdf
```

### Bug Bounty
```bash
# 1. Découverte assets
redsentinel osint --target company.com --github --cloud

# 2. Fuzzing
redsentinel fuzz --url https://api.company.com/endpoint --wordlist custom.txt

# 3. Tests spécifiques
redsentinel test-sqli --url https://company.com/page?id=1
```

### Red Team
```bash
# 1. Reconnaissance passive
redsentinel osint --target target.com --passive

# 2. Post-exploitation
redsentinel postexploit --target 192.168.1.100 --os linux

# 3. Lateral movement
redsentinel lateral --pivot-host 10.0.0.50
```

---

## Performance

### Optimisation Scans
```yaml
performance:
  max_cpu: 80.0
  max_memory: 80.0
  batch_size: 100
  cache_size: 1000
  workers: 8
```

### Multiprocessing
```python
from redsentinel.performance.optimizer import PerformanceOptimizer

optimizer = PerformanceOptimizer(config)
results = await optimizer.optimize_scan(targets, scan_func)
```

---

## Sécurité

### Utilisation Éthique
- Usage autorisé uniquement
- Autorisation écrite obligatoire
- Respect des lois locales
- Documentation de toutes actions

### Bonnes Pratiques
- Configuration des API keys
- Utilisation PostgreSQL en production
- Backup réguliers de la database
- Logs activés
- Audit trail

---

## Support

### Documentation
- START_HERE.md - Point de départ
- TRANSFORMATION_PROGRESS.md - Progression
- CHANGELOG_V7.md - Historique
- API Docs - http://localhost:8000/docs

### Contact
- Website: https://redsentinel.fr
- Email: support@redsentinel.fr
- GitHub: Issues

---

## Ressources

### Exemples
- `examples/` - Scripts d'exemple
- `tests/` - Tests unitaires
- `docs/` - Documentation API

### Configurations
- `config.yaml.example` - Template configuration
- `alembic.ini` - Configuration migrations
- `requirements.txt` - Dépendances

---

© 2024 Alexandre Tavares - Redsentinel. Usage Professionnel Uniquement.
