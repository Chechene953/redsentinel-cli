"""
Module de calcul de scores de sécurité et métriques d'audit
"""

import math


def calculate_security_score(vulnerabilities, weights=None):
    """
    Calcule le score de sécurité global sur 100
    
    Formule : 100 - (somme pondérée des vulnérabilités)
    
    Args:
        vulnerabilities: Liste de vulnérabilités avec CVSS scores
        weights: Dict de poids par sévérité (optionnel)
    
    Returns:
        dict avec score et détails
    """
    if weights is None:
        weights = {
            "CRITICAL": 5.0,  # CVSS 9.0-10.0
            "HIGH": 3.0,      # CVSS 7.0-8.9
            "MEDIUM": 1.5,    # CVSS 4.0-6.9
            "LOW": 0.5,       # CVSS 0.1-3.9
            "INFO": 0.1       # Informations
        }
    
    score_by_severity = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }
    
    total_deduction = 0.0
    max_possible_deduction = 100.0
    
    # Compter et pondérer les vulnérabilités
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN").upper()
        cvss_score = vuln.get("cvss_score", 0)
        
        # Déterminer la sévérité si absente
        if severity == "UNKNOWN" and cvss_score:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"
            else:
                severity = "INFO"
        
        if severity in score_by_severity:
            score_by_severity[severity] += 1
            weight = weights.get(severity, 1.0)
            
            # Déduction basée sur le poids
            if cvss_score:
                # Déduction = (CVSS/10) * weight
                deduction = (cvss_score / 10.0) * weight
            else:
                # Déduction par défaut basée sur la sévérité
                deduction = weight
            
            total_deduction += deduction
    
    # Calculer le score final
    final_score = max(0, 100 - total_deduction)
    
    # Niveau de risque global
    risk_level = determine_risk_level(final_score, vulnerabilities)
    
    return {
        "global_score": round(final_score, 1),
        "max_score": 100,
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities_by_severity": score_by_severity,
        "total_deduction": round(total_deduction, 2),
        "risk_level": risk_level,
        "grade": score_to_grade(final_score),
        "recommendations": generate_score_recommendations(final_score, score_by_severity)
    }


def determine_risk_level(score, vulnerabilities=None):
    """
    Détermine le niveau de risque global basé sur le score
    
    Args:
        score: Score de sécurité sur 100
        vulnerabilities: Optionnel, pour analyse plus fine
    
    Returns:
        str: CRITIQUE, ÉLEVÉ, MOYEN, FAIBLE
    """
    if score >= 80:
        return "FAIBLE"
    elif score >= 60:
        return "MOYEN"
    elif score >= 40:
        return "ÉLEVÉ"
    elif score >= 20:
        return "CRITIQUE"
    else:
        return "CRITIQUE"


def score_to_grade(score):
    """
    Convertit un score en note/grade
    
    Args:
        score: Score sur 100
    
    Returns:
        str: A+, A, B+, B, C, D, F
    """
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 85:
        return "B+"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


def generate_score_recommendations(score, vulnerabilities_by_severity):
    """
    Génère des recommandations basées sur le score
    
    Args:
        score: Score de sécurité
        vulnerabilities_by_severity: Dict avec compteurs par sévérité
    
    Returns:
        list de recommandations
    """
    recommendations = []
    
    # Recommandations basées sur la sévérité
    if vulnerabilities_by_severity.get("CRITICAL", 0) > 0:
        recommendations.append({
            "priority": "IMMEDIATE",
            "message": f"{vulnerabilities_by_severity['CRITICAL']} vulnérabilité(s) CRITIQUE détectée(s). Correction dans les 24-48h."
        })
    
    if vulnerabilities_by_severity.get("HIGH", 0) > 5:
        recommendations.append({
            "priority": "HIGH",
            "message": f"{vulnerabilities_by_severity['HIGH']} vulnérabilités ÉLEVÉES. Mise en place d'un plan de remédiation dans la semaine."
        })
    
    # Recommandations basées sur le score
    if score < 40:
        recommendations.append({
            "priority": "CRITICAL",
            "message": "Posture de sécurité CRITIQUE. Audit complet et remédiation urgente requise."
        })
    elif score < 60:
        recommendations.append({
            "priority": "HIGH",
            "message": "Posture de sécurité FAIBLE. Renforcement des contrôles de sécurité nécessaire."
        })
    elif score < 80:
        recommendations.append({
            "priority": "MEDIUM",
            "message": "Posture de sécurité correcte mais améliorable. Amélioration continue recommandée."
        })
    else:
        recommendations.append({
            "priority": "INFO",
            "message": "Posture de sécurité solide. Maintenir ce niveau par un programme de sécurité pérenne."
        })
    
    return recommendations


def calculate_component_scores(results_dict):
    """
    Calcule les scores par composant (Web, Infrastructure, etc.)
    
    Args:
        results_dict: Dict avec résultats par composant
    
    Returns:
        dict avec scores par composant
    """
    component_scores = {}
    
    # Web Application
    if "web_vulnerabilities" in results_dict:
        web_vulns = results_dict["web_vulnerabilities"]
        component_scores["Application Web"] = calculate_security_score(web_vulns)
    
    # Infrastructure
    if "infrastructure_vulnerabilities" in results_dict:
        infra_vulns = results_dict["infrastructure_vulnerabilities"]
        component_scores["Infrastructure Réseau"] = calculate_security_score(infra_vulns)
    
    # API
    if "api_vulnerabilities" in results_dict:
        api_vulns = results_dict["api_vulnerabilities"]
        component_scores["API REST"] = calculate_security_score(api_vulns)
    
    # Active Directory
    if "ad_vulnerabilities" in results_dict:
        ad_vulns = results_dict["ad_vulnerabilities"]
        component_scores["Active Directory"] = calculate_security_score(ad_vulns)
    
    return component_scores


def generate_security_summary(results_dict):
    """
    Génère un résumé de sécurité global
    
    Args:
        results_dict: Dict avec tous les résultats de scan
    
    Returns:
        dict avec résumé complet
    """
    # Collecter toutes les vulnérabilités
    all_vulnerabilities = []
    
    for key, value in results_dict.items():
        if "vulnerabilities" in key and isinstance(value, list):
            all_vulnerabilities.extend(value)
    
    # Calculer le score global
    global_score = calculate_security_score(all_vulnerabilities)
    
    # Calculer les scores par composant
    component_scores = calculate_component_scores(results_dict)
    
    # Statistiques globales
    severity_counts = global_score["vulnerabilities_by_severity"]
    total = global_score["total_vulnerabilities"]
    
    # Pourcentages
    percentages = {}
    for severity, count in severity_counts.items():
        if total > 0:
            percentages[severity] = round((count / total) * 100, 1)
        else:
            percentages[severity] = 0
    
    return {
        "global_score": global_score["global_score"],
        "risk_level": global_score["risk_level"],
        "grade": global_score["grade"],
        "total_vulnerabilities": total,
        "severity_distribution": {
            "counts": severity_counts,
            "percentages": percentages
        },
        "component_scores": component_scores,
        "recommendations": global_score["recommendations"],
        "summary_table": generate_summary_table(severity_counts, total)
    }


def generate_summary_table(severity_counts, total):
    """
    Génère un tableau de synthèse des résultats
    
    Args:
        severity_counts: Dict avec compteurs par sévérité
        total: Nombre total de vulnérabilités
    
    Returns:
        list de dicts pour affichage dans tableau
    """
    emoji_map = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪"
    }
    
    table = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(severity, 0)
        percentage = round((count / total * 100), 1) if total > 0 else 0
        
        # Exemple de vulnérabilité (pour affichage)
        example = get_example_for_severity(severity) if count > 0 else ""
        
        table.append({
            "severity": severity,
            "emoji": emoji_map.get(severity, ""),
            "count": count,
            "percentage": f"{percentage}%",
            "example": example
        })
    
    return table


def get_example_for_severity(severity):
    """Retourne un exemple de vulnérabilité par sévérité"""
    examples = {
        "CRITICAL": "Injection SQL permettant extraction de données",
        "HIGH": "Absence de validation JWT",
        "MEDIUM": "Versions logicielles obsolètes",
        "LOW": "En-têtes de sécurité manquants",
        "INFO": "Recommandations d'amélioration"
    }
    return examples.get(severity, "")

