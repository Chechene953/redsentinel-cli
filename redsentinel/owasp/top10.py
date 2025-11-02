"""
Module OWASP Top 10 - Mapping et classification des vulnérabilités
"""

# OWASP Top 10 2021 mapping
OWASP_2021 = {
    "A01:2021 - Broken Access Control": {
        "description": "Les contrôles d'accès qui permettent aux utilisateurs d'agir en dehors de leurs permissions prévues.",
        "examples": [
            "Elevation de privilèges",
            "Access control bypass",
            "IDOR (Insecure Direct Object Reference)",
            "Missing authentication",
            "Horizontal privilege escalation",
            "Vertical privilege escalation",
            "Force browsing",
            "Path traversal",
            "Insecure direct object reference"
        ],
        "severity": "HIGH",
        "cwe_ids": ["CWE-200", "CWE-284", "CWE-285", "CWE-352", "CWE-434", "CWE-693"]
    },
    "A02:2021 - Cryptographic Failures": {
        "description": "Vulnérabilités liées à la cryptographie défaillante ou absente, exposant des données sensibles.",
        "examples": [
            "Chiffrement faible ou absent",
            "Données sensibles transmises en clair",
            "Hashs faibles (MD5, SHA1)",
            "Clés cryptographiques faibles",
            "Certificats SSL/TLS expirés ou invalides",
            "Plaintext credentials",
            "Weak encryption",
            "Insecure storage",
            "Weak random number generation"
        ],
        "severity": "HIGH",
        "cwe_ids": ["CWE-256", "CWE-295", "CWE-296", "CWE-310", "CWE-327", "CWE-759"]
    },
    "A03:2021 - Injection": {
        "description": "Injections de code malveillant dans les entrées utilisateur non validées.",
        "examples": [
            "SQL injection",
            "NoSQL injection",
            "Command injection",
            "LDAP injection",
            "XPath injection",
            "OS command injection",
            "Code injection",
            "Expression language injection",
            "Template injection"
        ],
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-79", "CWE-89", "CWE-73", "CWE-78", "CWE-91"]
    },
    "A04:2021 - Insecure Design": {
        "description": "Défauts de conception de sécurité menant à des vulnérabilités structurelles.",
        "examples": [
            "Architecture fragile",
            "Principe de moindre privilège non respecté",
            "Pas de défense en profondeur",
            "Security by obscurity",
            "Weak threat modeling",
            "Insecure by default configuration",
            "Missing security controls"
        ],
        "severity": "HIGH",
        "cwe_ids": ["CWE-209", "CWE-213", "CWE-203", "CWE-215", "CWE-693"]
    },
    "A05:2021 - Security Misconfiguration": {
        "description": "Configuration de sécurité inappropriée ou manquante dans l'application.",
        "examples": [
            "Configuration par défaut faible",
            "Headers de sécurité manquants",
            "Erreurs détaillées exposées",
            "Debug mode activé en production",
            "Comptes par défaut non changés",
            "Directory listing enabled",
            "Verbose error messages",
            "Missing CORS configuration",
            "Insecure file permissions"
        ],
        "severity": "MEDIUM",
        "cwe_ids": ["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260"]
    },
    "A06:2021 - Vulnerable and Outdated Components": {
        "description": "Utilisation de composants avec vulnérabilités connues non corrigées.",
        "examples": [
            "Frameworks/libraries obsolètes",
            "CVE non corrigés",
            "Dependencies vulnérables",
            "OS non patchés",
            "Weak cryptographic libraries",
            "Unsupported software",
            "Missing security patches",
            "Outdated dependencies"
        ],
        "severity": "HIGH",
        "cwe_ids": ["CWE-1104", "CWE-132", "CWE-434", "CWE-502", "CWE-829"]
    },
    "A07:2021 - Identification and Authentication Failures": {
        "description": "Défauts dans les mécanismes d'authentification et d'identification.",
        "examples": [
            "Brute force possible",
            "Credential stuffing",
            "Session fixation",
            "Session hijacking",
            "Weak password policy",
            "Missing MFA",
            "Password reset vulnerabilities",
            "Credential exposure",
            "Insecure session management"
        ],
        "severity": "HIGH",
        "cwe_ids": ["CWE-287", "CWE-306", "CWE-307", "CWE-798", "CWE-640", "CWE-521"]
    },
    "A08:2021 - Software and Data Integrity Failures": {
        "description": "Violation de l'intégrité des logiciels et données critiques.",
        "examples": [
            "CI/CD pipeline compromis",
            "Deserialization non sécurisée",
            "Plugin/Tool compromis",
            "Supply chain attacks",
            "Insecure update mechanism",
            "Code integrity violations",
            "Untrusted data deserialization"
        ],
        "severity": "HIGH",
        "cwe_ids": ["CWE-345", "CWE-494", "CWE-502", "CWE-829"]
    },
    "A09:2021 - Security Logging and Monitoring Failures": {
        "description": "Absence ou insuffisance de logging et monitoring de sécurité.",
        "examples": [
            "Logs manquants ou incomplets",
            "Pas de détection d'incident",
            "Alertes mal configurées",
            "Logs non surveillés",
            "Missing audit trails",
            "No security event logging",
            "Insufficient log monitoring"
        ],
        "severity": "MEDIUM",
        "cwe_ids": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"]
    },
    "A10:2021 - Server-Side Request Forgery (SSRF)": {
        "description": "Forçage du serveur à faire des requêtes vers des ressources non autorisées.",
        "examples": [
            "SSRF vers localhost",
            "SSRF vers cloud metadata",
            "SSRF vers réseaux internes",
            "Blind SSRF",
            "SSRF avec chained attacks",
            "Metadata endpoint access",
            "Internal network enumeration via SSRF"
        ],
        "severity": "HIGH",
        "cwe_ids": ["CWE-918"]
    }
}

# Mots-clés pour matching automatique
KEYWORDS_MAPPING = {
    "A01:2021 - Broken Access Control": [
        "access control", "authorization", "privilege", "forbidden", "unauthorized",
        "idor", "direct object reference", "forced browsing", "path traversal",
        "directory traversal", "file inclusion", "arbitrary file"
    ],
    "A02:2021 - Cryptographic Failures": [
        "encryption", "crypto", "hash", "md5", "sha1", "aes", "ssl", "tls",
        "certificate", "password", "credentials", "sensitive data", "plaintext",
        "weak cipher"
    ],
    "A03:2021 - Injection": [
        "injection", "sql", "nosql", "command", "code injection", "xpath",
        "ldap", "template injection", "expression language", "os command"
    ],
    "A04:2021 - Insecure Design": [
        "design", "architecture", "threat modeling", "security by obscurity",
        "defense in depth", "principle"
    ],
    "A05:2021 - Security Misconfiguration": [
        "misconfiguration", "default", "debug", "error message", "exposed",
        "headers", "cors", "directory listing", "file permissions", "verbose"
    ],
    "A06:2021 - Vulnerable and Outdated Components": [
        "cve", "vulnerable", "outdated", "obsolete", "unpatched", "dependency",
        "library", "framework", "version", "patch", "update"
    ],
    "A07:2021 - Identification and Authentication Failures": [
        "authentication", "login", "password", "credential", "session",
        "brute force", "mfa", "2fa", "logout", "remember me"
    ],
    "A08:2021 - Software and Data Integrity Failures": [
        "integrity", "deserialization", "ci/cd", "pipeline", "supply chain",
        "plugin", "update mechanism"
    ],
    "A09:2021 - Security Logging and Monitoring Failures": [
        "logging", "monitoring", "audit", "log", "alert", "event", "incident",
        "detection"
    ],
    "A10:2021 - Server-Side Request Forgery (SSRF)": [
        "ssrf", "request forgery", "localhost", "metadata", "internal network",
        "blind ssrf"
    ]
}


def classify_vulnerability(vulnerability_name, vulnerability_description="", cve_id=None):
    """
    Classe une vulnérabilité dans les catégories OWASP Top 10
    
    Args:
        vulnerability_name: Nom de la vulnérabilité
        vulnerability_description: Description détaillée (optionnel)
        cve_id: ID CVE (optionnel)
    
    Returns:
        dict avec catégorie OWASP, confiance, et détails
    """
    text_to_analyze = (vulnerability_name + " " + vulnerability_description).lower()
    
    best_matches = []
    
    # Matching par mots-clés
    for category, keywords in KEYWORDS_MAPPING.items():
        matches = sum(1 for keyword in keywords if keyword in text_to_analyze)
        if matches > 0:
            confidence = min(100, matches * 30)  # Max 100% de confiance
            best_matches.append({
                "category": category,
                "confidence": confidence,
                "matches": matches,
                "keywords_found": [kw for kw in keywords if kw in text_to_analyze]
            })
    
    # Trier par confiance décroissante
    best_matches.sort(key=lambda x: x["confidence"], reverse=True)
    
    if best_matches:
        best_match = best_matches[0]
        category_info = OWASP_2021.get(best_match["category"], {})
        
        return {
            "owasp_category": best_match["category"],
            "confidence": best_match["confidence"],
            "description": category_info.get("description", ""),
            "severity": category_info.get("severity", "UNKNOWN"),
            "cwe_ids": category_info.get("cwe_ids", []),
            "examples": category_info.get("examples", []),
            "alternative_matches": best_matches[1:3]  # 2 alternatives
        }
    
    # Si aucun match, essayer par CVE si fourni
    if cve_id:
        # TODO: Mapping CVE -> CWE -> OWASP
        pass
    
    # Pas de match trouvé
    return {
        "owasp_category": "NON CLASSÉ",
        "confidence": 0,
        "description": "Vulnérabilité non classée dans l'OWASP Top 10",
        "severity": "UNKNOWN",
        "cwe_ids": [],
        "examples": []
    }


def map_vulnerabilities_to_owasp(vulnerabilities_list):
    """
    Mappe une liste de vulnérabilités vers OWASP Top 10
    
    Args:
        vulnerabilities_list: Liste de dicts avec vulnérabilités
    
    Returns:
        dict groupé par catégorie OWASP
    """
    owasp_mapping = {}
    
    for vuln in vulnerabilities_list:
        classification = classify_vulnerability(
            vuln.get("name", ""),
            vuln.get("description", ""),
            vuln.get("cve_id")
        )
        
        category = classification["owasp_category"]
        
        if category not in owasp_mapping:
            owasp_mapping[category] = {
                "vulnerabilities": [],
                "total_count": 0,
                "severity": classification["severity"],
                "description": classification["description"]
            }
        
        owasp_mapping[category]["vulnerabilities"].append({
            "original": vuln,
            "classification": classification
        })
        owasp_mapping[category]["total_count"] += 1
    
    return owasp_mapping


def get_owasp_summary(owasp_mapping):
    """
    Génère un résumé des vulnérabilités par catégorie OWASP
    
    Args:
        owasp_mapping: Résultat de map_vulnerabilities_to_owasp
    
    Returns:
        dict avec statistiques par catégorie
    """
    summary = {
        "total_categories": len(owasp_mapping),
        "total_vulnerabilities": 0,
        "by_severity": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        },
        "categories": []
    }
    
    for category, data in owasp_mapping.items():
        summary["total_vulnerabilities"] += data["total_count"]
        
        # Compter par sévérité
        severity = data.get("severity", "UNKNOWN")
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + data["total_count"]
        
        summary["categories"].append({
            "category": category,
            "count": data["total_count"],
            "severity": severity,
            "description": data["description"]
        })
    
    return summary


def generate_owasp_report_section(owasp_mapping, summary):
    """
    Génère une section HTML/Markdown pour le rapport sur OWASP Top 10
    
    Args:
        owasp_mapping: Résultat de map_vulnerabilities_to_owasp
        summary: Résultat de get_owasp_summary
    
    Returns:
        str formaté pour inclusion dans rapport
    """
    lines = []
    
    lines.append("# Mapping OWASP Top 10 2021\n")
    lines.append(f"**Total de catégories affectées**: {summary['total_categories']}")
    lines.append(f"**Total de vulnérabilités**: {summary['total_vulnerabilities']}\n")
    
    lines.append("## Résumé par Sévérité\n")
    for severity, count in summary["by_severity"].items():
        if count > 0:
            lines.append(f"- **{severity}**: {count} vulnérabilité(s)")
    
    lines.append("\n## Catégories Affectées\n\n")
    
    # Trier par sévérité puis par count
    sorted_categories = sorted(
        summary["categories"],
        key=lambda x: (x["severity"], x["count"]),
        reverse=True
    )
    
    for cat in sorted_categories:
        if cat["count"] > 0:
            lines.append(f"### {cat['category']}")
            lines.append(f"- **Description**: {cat['description']}")
            lines.append(f"- **Nombre de vulnérabilités**: {cat['count']}")
            lines.append(f"- **Sévérité**: {cat['severity']}\n")
    
    return "\n".join(lines)

