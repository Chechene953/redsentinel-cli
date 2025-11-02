"""
Module de génération de plans de remédiation priorisés
"""


def prioritize_vulnerabilities(vulnerabilities, timeline_config=None):
    """
    Priorise les vulnérabilités selon leur gravité et impact
    
    Args:
        vulnerabilities: Liste de vulnérabilités
        timeline_config: Dict avec délais (optionnel)
    
    Returns:
        dict avec vulnérabilités groupées par priorité
    """
    if timeline_config is None:
        timeline_config = {
            "immediate": 7,      # Jours
            "short_term": 30,    # Jours
            "medium_term": 90,   # Jours
            "long_term": 180     # Jours
        }
    
    prioritized = {
        "immediate": {
            "label": "Immédiat",
            "timeline": f"< {timeline_config['immediate']} jours",
            "vulnerabilities": [],
            "count": 0,
            "total_effort": 0
        },
        "short_term": {
            "label": "Court terme",
            "timeline": f"< {timeline_config['short_term']} jours",
            "vulnerabilities": [],
            "count": 0,
            "total_effort": 0
        },
        "medium_term": {
            "label": "Moyen terme",
            "timeline": f"< {timeline_config['medium_term']} jours",
            "vulnerabilities": [],
            "count": 0,
            "total_effort": 0
        },
        "long_term": {
            "label": "Long terme",
            "timeline": f"< {timeline_config['long_term']} jours",
            "vulnerabilities": [],
            "count": 0,
            "total_effort": 0
        }
    }
    
    # Trier les vulnérabilités par CVSS décroissant
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda x: x.get("cvss_score", 0),
        reverse=True
    )
    
    # Catégoriser chaque vulnérabilité
    for vuln in sorted_vulns:
        cvss_score = vuln.get("cvss_score", 0)
        severity = vuln.get("severity", "UNKNOWN").upper()
        
        # Déterminer la priorité
        if cvss_score >= 9.0 or severity == "CRITICAL":
            priority = "immediate"
        elif cvss_score >= 7.0 or severity == "HIGH":
            priority = "short_term"
        elif cvss_score >= 4.0 or severity == "MEDIUM":
            priority = "medium_term"
        else:
            priority = "long_term"
        
        # Ajouter à la catégorie
        prioritized[priority]["vulnerabilities"].append(vuln)
        prioritized[priority]["count"] += 1
        
        # Estimer l'effort (jours/homme)
        effort = estimate_remediation_effort(cvss_score, severity)
        prioritized[priority]["total_effort"] += effort
    
    return prioritized


def estimate_remediation_effort(cvss_score, severity):
    """
    Estime l'effort de correction en jours/homme
    
    Args:
        cvss_score: Score CVSS
        severity: Sévérité
    
    Returns:
        float: Jours/homme estimés
    """
    # Estimation basée sur CVSS
    if cvss_score >= 9.0 or severity == "CRITICAL":
        return 2.0  # 2 jours/homme pour critique
    elif cvss_score >= 7.0 or severity == "HIGH":
        return 1.0  # 1 jour/homme pour élevé
    elif cvss_score >= 4.0 or severity == "MEDIUM":
        return 0.5  # 0.5 jour/homme pour moyen
    else:
        return 0.25  # 0.25 jour/homme pour faible/info


def generate_remediation_plan(vulnerabilities, timeline_config=None):
    """
    Génère un plan de remédiation complet
    
    Args:
        vulnerabilities: Liste de vulnérabilités
        timeline_config: Configuration des délais
    
    Returns:
        dict avec plan de remédiation complet
    """
    prioritized = prioritize_vulnerabilities(vulnerabilities, timeline_config)
    
    plan = {
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "total_effort_days": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        },
        "phases": prioritized,
        "timeline_visual": generate_timeline_visual(prioritized)
    }
    
    # Calculer le total d'effort
    for phase in prioritized.values():
        plan["summary"]["total_effort_days"] += phase["total_effort"]
        
        # Compter par sévérité
        for vuln in phase["vulnerabilities"]:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity == "CRITICAL":
                plan["summary"]["critical_count"] += 1
            elif severity == "HIGH":
                plan["summary"]["high_count"] += 1
            elif severity == "MEDIUM":
                plan["summary"]["medium_count"] += 1
            else:
                plan["summary"]["low_count"] += 1
    
    return plan


def generate_timeline_visual(prioritized):
    """
    Génère une représentation visuelle ASCII de la timeline
    
    Args:
        prioritized: Dict avec vulnérabilités priorisées
    
    Returns:
        str: Timeline ASCII
    """
    lines = []
    
    for phase_name, phase_data in prioritized.items():
        if phase_data["count"] > 0:
            label = phase_data["label"]
            count = phase_data["count"]
            timeline = phase_data["timeline"]
            effort = phase_data["total_effort"]
            
            # Barre ASCII
            bar_length = min(50, int(count * 2))
            bar = "█" * bar_length + "░" * (50 - bar_length)
            
            line = f"{label:15} [{bar}] {count:2} vuln(s) | {effort:4.1f} j/h"
            lines.append(line)
    
    return "\n".join(lines)


def generate_raci_matrix(vulnerabilities_by_type):
    """
    Génère une matrice RACI basique
    
    Args:
        vulnerabilities_by_type: Dict groupé par type de vulnérabilité
    
    Returns:
        dict avec matrice RACI
    """
    raci = {
        "responsibilities": {
            "Dev Lead": [],
            "DevOps": [],
            "Security Team": [],
            "DBA": [],
            "Infrastructure": []
        }
    }
    
    # Mapping basique type -> responsabilité
    type_to_role = {
        "application": "Dev Lead",
        "infrastructure": "DevOps",
        "network": "Infrastructure",
        "database": "DBA",
        "api": "Dev Lead",
        "web": "Dev Lead",
        "authentication": "Security Team"
    }
    
    for vuln_type, vulns in vulnerabilities_by_type.items():
        role = type_to_role.get(vuln_type, "Dev Lead")
        if role in raci["responsibilities"]:
            raci["responsibilities"][role].extend(vulns)
    
    return raci


def calculate_budget_estimate(remediation_plan):
    """
    Estime le budget de remédiation
    
    Args:
        remediation_plan: Plan de remédiation
    
    Returns:
        dict avec estimations budgétaires
    """
    # Coûts par catégorie (en euros par jour/homme)
    daily_rate = {
        "immediate": 800,    # Urgence = tarif premium
        "short_term": 700,   # Court terme
        "medium_term": 600,  # Moyen terme
        "long_term": 500     # Long terme
    }
    
    budget = {
        "phases": {},
        "total_cost": 0.0
    }
    
    for phase_name, phase_data in remediation_plan["phases"].items():
        if phase_data["count"] > 0:
            effort = phase_data["total_effort"]
            rate = daily_rate.get(phase_name, 600)
            cost = effort * rate
            
            budget["phases"][phase_name] = {
                "effort_days": effort,
                "rate_per_day": rate,
                "total_cost": round(cost, 2)
            }
            
            budget["total_cost"] += cost
    
    budget["total_cost"] = round(budget["total_cost"], 2)
    
    return budget

