"""
Module de mapping de conformité (RGPD, PCI-DSS, ISO 27001, NIST, CWE Top 25)
Mapping complet vers tous les standards de sécurité majeurs
"""

from typing import Dict, List, Optional
from redsentinel.vulns.cve_cwe_mapper import cwe_to_owasp


# Mapping RGPD
RGPD_MAPPING = {
    "Art. 32 - Sécurité du traitement": {
        "description": "Sécurité du traitement des données personnelles",
        "requirements": [
            "Chiffrement des données sensibles",
            "Authentification forte",
            "Gestion des accès (principe du moindre privilège)",
            "Traçabilité et audit logs",
            "Sauvegarde sécurisée"
        ],
        "related_vulns": [
            "Weak encryption",
            "Missing authentication",
            "Privilege escalation",
            "Missing logging",
            "Insecure storage"
        ]
    },
    "Art. 33 - Notification de violation": {
        "description": "Notification en cas de violation de données personnelles",
        "requirements": [
            "Procédures de détection d'incident",
            "SIEM/SOC opérationnel",
            "Plan de réponse aux incidents",
            "Journalisation complète"
        ],
        "related_vulns": [
            "Missing monitoring",
            "Insufficient logging",
            "No incident response plan",
            "Weak detection"
        ]
    },
    "Art. 25 - Privacy by design": {
        "description": "Protection des données dès la conception",
        "requirements": [
            "Chiffrement end-to-end",
            "Minimisation des données",
            "Pseudonymisation",
            "DPO impliqué en conception"
        ],
        "related_vulns": [
            "Data exposure",
            "Excessive data collection",
            "Missing anonymization",
            "Privacy violations"
        ]
    },
    "Art. 28 - Sous-traitants": {
        "description": "Responsabilité des sous-traitants",
        "requirements": [
            "Clauses de sécurité dans contrats",
            "Audit des sous-traitants",
            "Conformité des tiers"
        ],
        "related_vulns": [
            "Third-party vulnerabilities",
            "Unpatched dependencies",
            "Supply chain risks"
        ]
    }
}


# Mapping PCI-DSS (pour les entreprises e-commerce)
PCI_DSS_MAPPING = {
    "Req 1 - Firewall": {
        "description": "Configuration firewall et segmentation réseau",
        "requirements": [
            "Firewall rules restrictives",
            "Segmentation DMZ",
            "Restrictions réseau"
        ],
        "related_vulns": [
            "Open ports",
            "Missing firewall",
            "Network misconfiguration"
        ]
    },
    "Req 2 - Default passwords": {
        "description": "Absence de mots de passe par défaut",
        "requirements": [
            "Aucun mot de passe par défaut",
            "Changement à la première connexion",
            "Mots de passe complexes"
        ],
        "related_vulns": [
            "Default credentials",
            "Weak password policy",
            "Hardcoded passwords"
        ]
    },
    "Req 4 - Encryption": {
        "description": "Chiffrement des données sensibles en transit",
        "requirements": [
            "TLS 1.2+",
            "Ciphers forts",
            "Certificats valides"
        ],
        "related_vulns": [
            "Weak SSL/TLS",
            "Self-signed certificates",
            "Weak ciphers"
        ]
    },
    "Req 7 - Access control": {
        "description": "Contrôle d'accès strict",
        "requirements": [
            "Principe du moindre privilège",
            "Séparation des rôles",
            "Authentification forte"
        ],
        "related_vulns": [
            "Privilege escalation",
            "Missing access control",
            "Horizontal/vertical bypass"
        ]
    }
}


# Mapping ISO 27001
ISO_27001_MAPPING = {
    "A.9 - Gestion des accès": {
        "description": "Contrôle d'accès aux systèmes d'information",
        "requirements": [
            "Politique d'accès",
            "Authentification utilisateur",
            "Gestion des privilèges",
            "Contrôle d'accès réseau"
        ],
        "related_vulns": [
            "Weak authentication",
            "Privilege escalation",
            "Missing access control",
            "Unsecured network"
        ]
    },
    "A.12 - Sécurité opérationnelle": {
        "description": "Gestion opérationnelle de la sécurité",
        "requirements": [
            "Gestion des patches",
            "Protection contre malware",
            "Sauvegarde",
            "Monitoring"
        ],
        "related_vulns": [
            "Unpatched systems",
            "Missing antivirus",
            "No backups",
            "Insufficient monitoring"
        ]
    },
    "A.14 - Développement": {
        "description": "Sécurité dans le cycle de développement",
        "requirements": [
            "SDLC sécurisé",
            "Review de code",
            "Tests de sécurité",
            "Gestion des changements"
        ],
        "related_vulns": [
            "SQL injection",
            "XSS",
            "Weak cryptography",
            "Logic vulnerabilities"
        ]
    }
}


def map_vulnerability_to_compliance(vulnerability, standards=None):
    """
    Mappe une vulnérabilité aux exigences de conformité
    
    Args:
        vulnerability: Dict avec info vulnérabilité
        standards: Liste de standards à vérifier (RGPD, PCI-DSS, ISO 27001)
    
    Returns:
        dict avec exigences de conformité affectées
    """
    if standards is None:
        standards = ["RGPD", "PCI-DSS", "ISO_27001"]
    
    mapping = {
        "RGPD": [],
        "PCI-DSS": [],
        "ISO_27001": []
    }
    
    vuln_name = vulnerability.get("name", "").lower()
    vuln_description = vulnerability.get("description", "").lower()
    text = f"{vuln_name} {vuln_description}"
    
    # Check RGPD
    if "RGPD" in standards:
        for article, details in RGPD_MAPPING.items():
            for keyword in details["related_vulns"]:
                if keyword.lower() in text:
                    mapping["RGPD"].append({
                        "article": article,
                        "description": details["description"],
                        "compliance_status": "NON CONFORME"
                    })
                    break
    
    # Check PCI-DSS
    if "PCI-DSS" in standards:
        for requirement, details in PCI_DSS_MAPPING.items():
            for keyword in details["related_vulns"]:
                if keyword.lower() in text:
                    mapping["PCI-DSS"].append({
                        "requirement": requirement,
                        "description": details["description"],
                        "compliance_status": "NON CONFORME"
                    })
                    break
    
    # Check ISO 27001
    if "ISO_27001" in standards:
        for control, details in ISO_27001_MAPPING.items():
            for keyword in details["related_vulns"]:
                if keyword.lower() in text:
                    mapping["ISO_27001"].append({
                        "control": control,
                        "description": details["description"],
                        "compliance_status": "NON CONFORME"
                    })
                    break
    
    return mapping


def analyze_compliance(vulnerabilities, standards=None):
    """
    Analyse la conformité globale par standard
    
    Args:
        vulnerabilities: Liste de vulnérabilités
        standards: Standards à analyser
    
    Returns:
        dict avec analyse de conformité
    """
    if standards is None:
        standards = ["RGPD", "PCI-DSS", "ISO_27001"]
    
    compliance_status = {}
    
    for standard in standards:
        compliance_status[standard] = {
            "standards_affected": [],
            "non_conform_items": [],
            "total_issues": 0,
            "compliance_level": "UNKNOWN"
        }
    
    # Analyser chaque vulnérabilité
    for vuln in vulnerabilities:
        mapping = map_vulnerability_to_compliance(vuln, standards)
        
        for standard, issues in mapping.items():
            if issues:
                compliance_status[standard]["non_conform_items"].extend(issues)
                compliance_status[standard]["total_issues"] += len(issues)
    
    # Calculer le niveau de conformité pour chaque standard
    for standard, status in compliance_status.items():
        total_items = compliance_status[standard]["total_issues"]
        
        if total_items == 0:
            compliance_level = "CONFORME"
        elif total_items <= 2:
            compliance_level = "PARTIEL"
        elif total_items <= 5:
            compliance_level = "NON CONFORME - MINOR"
        else:
            compliance_level = "NON CONFORME - MAJOR"
        
        compliance_status[standard]["compliance_level"] = compliance_level
    
    return compliance_status


def generate_compliance_recommendations(compliance_analysis):
    """
    Génère des recommandations de conformité
    
    Args:
        compliance_analysis: Résultat de analyze_compliance
    
    Returns:
        list de recommandations
    """
    recommendations = []
    
    for standard, status in compliance_analysis.items():
        if status["compliance_level"] != "CONFORME":
            recommendations.append({
                "standard": standard,
                "level": status["compliance_level"],
                "issues_count": status["total_issues"],
                "priority": "HIGH" if "MAJOR" in status["compliance_level"] else "MEDIUM",
                "recommendations": generate_standard_specific_recommendations(standard, status)
            })
    
    return recommendations


def generate_standard_specific_recommendations(standard, status):
    """
    Génère des recommandations spécifiques par standard
    
    Args:
        standard: Nom du standard
        status: Statut de conformité
    
    Returns:
        list de recommandations
    """
    recommendations = []
    
    if standard == "RGPD":
        recommendations.extend([
            "Désigner un DPO et l'impliquer dès la conception",
            "Implémenter le chiffrement end-to-end pour données sensibles",
            "Mettre à jour le registre des traitements",
            "Tester le plan de réponse aux incidents"
        ])
    
    elif standard == "PCI-DSS":
        recommendations.extend([
            "Effectuer un audit PCI-DSS complet",
            "Renforcer les contrôles d'accès",
            "Implémenter le chiffrement des données de carte",
            "Mettre en place monitoring et alerting"
        ])
    
    elif standard == "ISO_27001":
        recommendations.extend([
            "Mettre en place un ISMS (Information Security Management System)",
            "Effectuer une analyse de risques",
            "Établir des politiques de sécurité",
            "Former le personnel aux bonnes pratiques"
        ])
    
    return recommendations

