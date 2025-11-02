"""
Module de génération de rapports PDF professionnels
"""

import os
from datetime import datetime


def generate_audit_pdf(audit_data, output_path=None):
    """
    Génère un rapport PDF professionnel pour audit
    
    Args:
        audit_data: Dict avec toutes les données d'audit
        output_path: Chemin de sortie (optionnel)
    
    Returns:
        str: Chemin du fichier généré
    """
    # Pour l'instant, on génère un rapport HTML avancé
    # TODO: Intégrer WeasyPrint ou ReportLab pour PDF
    
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"report_audit_{timestamp}.html"
    
    html_content = generate_audit_html_report(audit_data)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return output_path


def generate_audit_html_report(audit_data):
    """
    Génère un rapport HTML complet basé sur vos templates AUDIT.md
    
    Args:
        audit_data: Dict avec toutes les données
    
    Returns:
        str: Contenu HTML
    """
    # Import des modules nécessaires
    from redsentinel.audit.scoring import generate_security_summary
    from redsentinel.audit.remediation import generate_remediation_plan
    from redsentinel.audit.compliance import analyze_compliance
    from redsentinel.audit.poc_generator import format_vulnerability_for_report
    
    # Générer les sections
    summary = generate_security_summary(audit_data)
    remediation = generate_remediation_plan(
        audit_data.get("vulnerabilities", []),
        audit_data.get("timeline_config")
    )
    
    # Analyser conformité
    compliance_std = audit_data.get("compliance_standards", ["RGPD", "PCI-DSS"])
    compliance = analyze_compliance(
        audit_data.get("vulnerabilities", []),
        compliance_std
    )
    
    # Formatter les vulnérabilités
    formatted_vulns = []
    for vuln in audit_data.get("vulnerabilities", []):
        formatted_vulns.append(format_vulnerability_for_report(vuln))
    
    # Client info
    client_name = audit_data.get("client_name", "[NOM DU CLIENT]")
    contract_ref = audit_data.get("contract_ref", "[REF-XXXX-YYYY]")
    audit_type = audit_data.get("audit_type", "Pentest")
    period_start = audit_data.get("period_start", "[DATE DÉBUT]")
    period_end = audit_data.get("period_end", "[DATE FIN]")
    report_date = audit_data.get("report_date", datetime.now().strftime("%d/%m/%Y"))
    
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit de Sécurité - {client_name}</title>
    <style>
        @page {{
            size: A4;
            margin: 2cm;
        }}
        body {{
            font-family: 'DejaVu Sans', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #ffffff;
        }}
        .header {{
            border-bottom: 3px solid #e00;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .logo-section {{
            text-align: center;
            margin-bottom: 20px;
        }}
        .company-name {{
            font-size: 24px;
            font-weight: bold;
            color: #e00;
        }}
        h1 {{
            color: #e00;
            border-bottom: 2px solid #e00;
            padding-bottom: 10px;
            margin-top: 30px;
        }}
        h2 {{
            color: #333;
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }}
        h3 {{
            color: #555;
            margin-top: 20px;
        }}
        .info-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .info-table th, .info-table td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}
        .info-table th {{
            background-color: #e00;
            color: white;
            font-weight: bold;
        }}
        .info-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .severity-critical {{ background-color: #8b0000; color: white; padding: 3px 8px; border-radius: 3px; }}
        .severity-high {{ background-color: #cc6600; color: white; padding: 3px 8px; border-radius: 3px; }}
        .severity-medium {{ background-color: #ffcc00; color: black; padding: 3px 8px; border-radius: 3px; }}
        .severity-low {{ background-color: #6699ff; color: white; padding: 3px 8px; border-radius: 3px; }}
        .severity-info {{ background-color: #ccc; color: black; padding: 3px 8px; border-radius: 3px; }}
        .vulnerability-card {{
            background: #f5f5f5;
            border-left: 4px solid #e00;
            padding: 15px;
            margin: 20px 0;
        }}
        .vulnerability-card.critical {{ border-left-color: #8b0000; }}
        .vulnerability-card.high {{ border-left-color: #cc6600; }}
        .vulnerability-card.medium {{ border-left-color: #ffcc00; }}
        .vulnerability-card.low {{ border-left-color: #6699ff; }}
        .executive-summary {{
            background: #fff5f5;
            border: 1px solid #e00;
            padding: 20px;
            margin: 20px 0;
        }}
        .score-box {{
            display: inline-block;
            background: #e00;
            color: white;
            padding: 15px 25px;
            border-radius: 5px;
            font-size: 32px;
            font-weight: bold;
            margin: 10px 0;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 3px solid #e00;
        }}
        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 12px;
            color: #666;
            text-align: center;
        }}
        .compliance-status {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .compliant {{ background: #4CAF50; color: white; }}
        .partial {{ background: #FFC107; color: black; }}
        .non-compliant {{ background: #F44336; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-section">
            <div class="company-name">REDSENTINEL</div>
            <div style="font-size: 14px; color: #666;">Audit de Sécurité Professionnel</div>
        </div>
    </div>

    <h1>Rapport d'Audit de Sécurité</h1>

    <table class="info-table">
        <tr><th colspan="2">Informations Contractuelles</th></tr>
        <tr><td><strong>Client</strong></td><td>{client_name}</td></tr>
        <tr><td><strong>Référence contrat</strong></td><td>{contract_ref}</td></tr>
        <tr><td><strong>Type d'audit</strong></td><td>{audit_type}</td></tr>
        <tr><td><strong>Période d'intervention</strong></td><td>du {period_start} au {period_end}</td></tr>
        <tr><td><strong>Date du rapport</strong></td><td>{report_date}</td></tr>
        <tr><td><strong>Classification</strong></td><td><strong>CONFIDENTIEL - DIFFUSION RESTREINTE</strong></td></tr>
    </table>

    <h2>Résumé Exécutif</h2>
    
    <div class="executive-summary">
        <h3>Score de Sécurité Global</h3>
        <div class="score-box">{summary['global_score']}/100</div>
        <p><strong>Niveau de risque :</strong> <span class="severity-{summary['risk_level'].lower()}">{summary['risk_level']}</span></p>
        <p><strong>Note :</strong> {summary['grade']}</p>
        
        <h3>Synthèse des Résultats</h3>
        <table class="info-table">
            <tr>
                <th>Gravité</th>
                <th>Nombre</th>
                <th>Exemples clés</th>
            </tr>"""
    
    # Tableau de synthèse
    for row in summary.get('summary_table', []):
        html += f"""
            <tr>
                <td><span class="severity-{row['severity'].lower()}">{row['emoji']} {row['severity']}</span></td>
                <td>{row['count']}</td>
                <td>{row['example']}</td>
            </tr>"""
    
    html += f"""
        </table>
        
        <h3>Recommandations Prioritaires</h3>
        <ol>"""
    
    # Top recommandations
    top_recs = summary.get('recommendations', [])[:3]
    for rec in top_recs:
        priority = rec.get('priority', 'INFO')
        html += f"""<li><strong>{rec['message']}</strong> - Délai : Immédiat</li>"""
    
    html += """</ol>
    </div>

    <h2>Résultats Détaillés</h2>"""
    
    # Affichage des vulnérabilités
    for vuln in formatted_vulns[:10]:  # Limiter à 10 pour l'exemple
        severity_class = vuln['severity'].lower()
        html += f"""
    <div class="vulnerability-card {severity_class}">
        <h3>[{vuln['id']}] {vuln['title']}</h3>
        <p><strong>Gravité :</strong> <span class="severity-{severity_class}">{vuln['severity']}</span></p>
        <p><strong>CVSS v3.1 :</strong> {vuln['cvss_score']}</p>
        <p><strong>CWE :</strong> {vuln.get('cwe', 'N/A')}</p>
        <p><strong>Localisation :</strong> <code>{vuln['location']}</code></p>
        
        <h4>Description Technique</h4>
        <p>{vuln['description']}</p>
        
        <h4>Preuve de Concept (PoC)</h4>
        <pre>{vuln.get('poc', 'PoC non fourni')}</pre>
        
        <h4>Impact Métier</h4>
        <p>{vuln.get('impact', 'Impact significatif sur la sécurité et la confidentialité des données')}</p>
        
        <h4>Recommandations de Correction</h4>
        <p>{vuln.get('remediation', 'Mettre en place des contrôles de sécurité appropriés')}</p>
    </div>"""
    
    html += f"""
    <h2>Plan de Remédiation</h2>
    
    <h3>Roadmap Priorisée</h3>
    <pre>{remediation.get('timeline_visual', 'N/A')}</pre>
    
    <h3>Budget Estimé</h3>
    """
    
    # TODO: Add budget section
    
    html += f"""
    <h2>Conformité Réglementaire</h2>
    """
    
    # Section conformité
    for standard, status in compliance.items():
        if status['total_issues'] > 0:
            compliance_class = "non-compliant" if "NON CONFORME" in status['compliance_level'] else "partial"
            html += f"""
    <h3>{standard}</h3>
    <p><strong>Niveau de conformité :</strong> <span class="compliance-status {compliance_class}">{status['compliance_level']}</span></p>
    <p><strong>Nombre d'éléments non conformes :</strong> {status['total_issues']}</p>
    """
    
    # Footer
    html += """
    <div class="footer">
        <p><strong>RedSentinel SAS</strong> - Alexandre Tavares</p>
        <p>alex@redsentinel.fr | +33 6 43 05 35 42</p>
        <p style="margin-top: 20px;">Ce rapport est confidentiel et destiné exclusivement au client dans le cadre de la mission contractuelle.</p>
        <p style="color: #666;">Classification : CONFIDENTIEL - DIFFUSION RESTREINTE</p>
        <p style="color: #999; font-size: 10px; margin-top: 30px;">Ce document a été généré automatiquement par RedSentinel. Alexandre Tavares et Redsentinel ne peuvent être tenus responsables de toute utilisation non autorisée de cet outil ou de toute activité malveillante.</p>
    </div>
</body>
</html>"""
    
    return html

