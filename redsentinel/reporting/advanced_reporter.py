"""
RedSentinel - Advanced Reporting Engine
Author: Alexandre Tavares - Redsentinel
Version: 7.0

Professional reporting with:
- Multiple formats (PDF, HTML, JSON, XML, CSV, Markdown)
- Charts & graphs
- Compliance mapping (OWASP ASVS, PCI-DSS, NIST, ISO 27001)
- Executive vs Technical reports
- Diff reports (scan comparisons)
- Custom branding
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import base64

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Report configuration"""
    format: str = 'pdf'  # pdf, html, json, xml, csv, markdown
    template: str = 'professional'  # professional, executive, technical, minimal
    include_charts: bool = True
    include_remediation: bool = True
    include_compliance: bool = True
    compliance_frameworks: List[str] = field(default_factory=lambda: ['OWASP-ASVS', 'PCI-DSS'])
    branding: Optional[Dict[str, str]] = None  # logo, colors, company_name
    language: str = 'en'  # en, fr, es, de


@dataclass
class ScanResults:
    """Scan results for reporting"""
    scan_id: str
    target: str
    start_time: datetime
    end_time: datetime
    duration: float
    vulnerabilities: List[Dict[str, Any]]
    statistics: Dict[str, int]
    recommendations: List[str]
    executive_summary: Optional[str] = None


class ComplianceMapper:
    """
    Map vulnerabilities to compliance frameworks
    """
    
    # OWASP ASVS v4.0 Mapping
    OWASP_ASVS = {
        'XSS': ['V5.3.3', 'V5.3.4', 'V5.3.6'],
        'SQL Injection': ['V5.3.4', 'V5.3.5'],
        'Authentication Failures': ['V2.1.1', 'V2.1.2', 'V2.1.3', 'V2.1.7'],
        'Broken Access Control': ['V4.1.1', 'V4.1.2', 'V4.1.3', 'V4.2.1'],
        'CSRF': ['V4.2.1', 'V4.2.2'],
        'Security Misconfiguration': ['V14.1.1', 'V14.1.2', 'V14.2.1'],
        'SSRF': ['V12.5.1', 'V12.5.2'],
        'Cryptographic Failures': ['V6.2.1', 'V6.2.2', 'V6.2.3', 'V6.2.4']
    }
    
    # PCI-DSS v4.0 Mapping
    PCI_DSS = {
        'XSS': ['6.5.7', '11.3.2'],
        'SQL Injection': ['6.5.1', '11.3.2'],
        'Authentication Failures': ['8.2.1', '8.2.3', '8.2.4'],
        'Broken Access Control': ['7.1.1', '7.1.2', '7.2.1'],
        'Cryptographic Failures': ['3.4.1', '3.5.1', '4.1.1'],
        'Security Misconfiguration': ['2.2.1', '2.2.2', '2.2.4']
    }
    
    # NIST SP 800-53 Rev. 5 Mapping
    NIST_800_53 = {
        'XSS': ['SI-10', 'SI-11'],
        'SQL Injection': ['SI-10', 'SI-11'],
        'Authentication Failures': ['IA-2', 'IA-5', 'IA-8'],
        'Broken Access Control': ['AC-3', 'AC-6', 'AC-17'],
        'Cryptographic Failures': ['SC-8', 'SC-12', 'SC-13'],
        'Security Misconfiguration': ['CM-6', 'CM-7', 'SI-2']
    }
    
    # ISO 27001:2013 Mapping
    ISO_27001 = {
        'XSS': ['A.14.1.2', 'A.14.1.3'],
        'SQL Injection': ['A.14.1.2', 'A.14.1.3'],
        'Authentication Failures': ['A.9.2.1', 'A.9.2.4', 'A.9.4.3'],
        'Broken Access Control': ['A.9.1.1', 'A.9.1.2', 'A.9.2.3'],
        'Cryptographic Failures': ['A.10.1.1', 'A.10.1.2'],
        'Security Misconfiguration': ['A.12.6.1', 'A.14.2.1']
    }
    
    @classmethod
    def map_vulnerability(cls, vuln_type: str, framework: str) -> List[str]:
        """
        Map vulnerability type to compliance controls
        
        Args:
            vuln_type: Type of vulnerability
            framework: Compliance framework (OWASP-ASVS, PCI-DSS, NIST, ISO-27001)
        
        Returns:
            List of relevant compliance controls
        """
        mapping = {
            'OWASP-ASVS': cls.OWASP_ASVS,
            'PCI-DSS': cls.PCI_DSS,
            'NIST-800-53': cls.NIST_800_53,
            'ISO-27001': cls.ISO_27001
        }
        
        framework_map = mapping.get(framework, {})
        
        # Fuzzy matching
        for key in framework_map:
            if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                return framework_map[key]
        
        return []


class ChartGenerator:
    """
    Generate charts and visualizations for reports
    """
    
    def __init__(self):
        try:
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
            import matplotlib.pyplot as plt
            self.plt = plt
            self.available = True
        except ImportError:
            logger.warning("matplotlib not available, charts disabled")
            self.available = False
    
    def generate_severity_pie_chart(self, statistics: Dict[str, int]) -> Optional[str]:
        """
        Generate pie chart of vulnerability severities
        
        Returns:
            Base64 encoded PNG image
        """
        if not self.available:
            return None
        
        try:
            # Extract severity data
            severities = {
                'Critical': statistics.get('critical', 0),
                'High': statistics.get('high', 0),
                'Medium': statistics.get('medium', 0),
                'Low': statistics.get('low', 0),
                'Info': statistics.get('info', 0)
            }
            
            # Filter out zero values
            severities = {k: v for k, v in severities.items() if v > 0}
            
            if not severities:
                return None
            
            # Create pie chart
            fig, ax = self.plt.subplots(figsize=(8, 6))
            
            colors = {
                'Critical': '#8B0000',  # Dark red
                'High': '#FF4444',      # Red
                'Medium': '#FFA500',    # Orange
                'Low': '#FFD700',       # Gold
                'Info': '#4169E1'       # Blue
            }
            
            chart_colors = [colors[k] for k in severities.keys()]
            
            ax.pie(
                severities.values(),
                labels=severities.keys(),
                autopct='%1.1f%%',
                colors=chart_colors,
                startangle=90
            )
            
            ax.set_title('Vulnerabilities by Severity', fontsize=14, fontweight='bold')
            
            # Save to base64
            import io
            buf = io.BytesIO()
            self.plt.savefig(buf, format='png', bbox_inches='tight', dpi=150)
            buf.seek(0)
            
            img_base64 = base64.b64encode(buf.read()).decode()
            
            self.plt.close(fig)
            
            return img_base64
        
        except Exception as e:
            logger.error(f"Error generating pie chart: {e}")
            return None
    
    def generate_category_bar_chart(self, vulnerabilities: List[Dict[str, Any]]) -> Optional[str]:
        """
        Generate bar chart of vulnerability categories
        
        Returns:
            Base64 encoded PNG image
        """
        if not self.available:
            return None
        
        try:
            # Count by category
            categories = {}
            for vuln in vulnerabilities:
                category = vuln.get('category', 'Unknown')
                categories[category] = categories.get(category, 0) + 1
            
            if not categories:
                return None
            
            # Sort by count
            sorted_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Create bar chart
            fig, ax = self.plt.subplots(figsize=(10, 6))
            
            names = [c[0] for c in sorted_categories]
            values = [c[1] for c in sorted_categories]
            
            bars = ax.barh(names, values, color='#4169E1')
            
            # Add value labels
            for i, bar in enumerate(bars):
                width = bar.get_width()
                ax.text(width, bar.get_y() + bar.get_height()/2,
                       f'{int(width)}',
                       ha='left', va='center', fontsize=10)
            
            ax.set_xlabel('Number of Vulnerabilities', fontsize=12)
            ax.set_title('Top 10 Vulnerability Categories', fontsize=14, fontweight='bold')
            ax.invert_yaxis()  # Highest at top
            
            self.plt.tight_layout()
            
            # Save to base64
            import io
            buf = io.BytesIO()
            self.plt.savefig(buf, format='png', bbox_inches='tight', dpi=150)
            buf.seek(0)
            
            img_base64 = base64.b64encode(buf.read()).decode()
            
            self.plt.close(fig)
            
            return img_base64
        
        except Exception as e:
            logger.error(f"Error generating bar chart: {e}")
            return None


class AdvancedReportGenerator:
    """
    Advanced report generator with multiple formats
    """
    
    def __init__(self, config: ReportConfig):
        self.config = config
        self.compliance_mapper = ComplianceMapper()
        self.chart_generator = ChartGenerator()
    
    async def generate_report(
        self,
        scan_results: ScanResults,
        output_path: Path
    ) -> bool:
        """
        Generate report in specified format
        
        Args:
            scan_results: Scan results to report
            output_path: Output file path
        
        Returns:
            True if successful
        """
        logger.info(f"Generating {self.config.format} report for scan {scan_results.scan_id}")
        
        try:
            if self.config.format == 'pdf':
                return await self._generate_pdf(scan_results, output_path)
            elif self.config.format == 'html':
                return await self._generate_html(scan_results, output_path)
            elif self.config.format == 'json':
                return await self._generate_json(scan_results, output_path)
            elif self.config.format == 'xml':
                return await self._generate_xml(scan_results, output_path)
            elif self.config.format == 'csv':
                return await self._generate_csv(scan_results, output_path)
            elif self.config.format == 'markdown':
                return await self._generate_markdown(scan_results, output_path)
            else:
                logger.error(f"Unsupported format: {self.config.format}")
                return False
        
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            return False
    
    async def _generate_pdf(self, scan_results: ScanResults, output_path: Path) -> bool:
        """Generate PDF report"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            
            # Create PDF
            doc = SimpleDocTemplate(str(output_path), pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            # Title page
            if self.config.branding and self.config.branding.get('company_name'):
                company = Paragraph(self.config.branding['company_name'], title_style)
                story.append(company)
                story.append(Spacer(1, 0.2*inch))
            
            title = Paragraph("Security Assessment Report", title_style)
            story.append(title)
            story.append(Spacer(1, 0.5*inch))
            
            # Executive summary
            if scan_results.executive_summary:
                story.append(Paragraph("Executive Summary", styles['Heading2']))
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph(scan_results.executive_summary, styles['BodyText']))
                story.append(Spacer(1, 0.3*inch))
            
            # Scan information
            story.append(Paragraph("Scan Information", styles['Heading2']))
            story.append(Spacer(1, 0.1*inch))
            
            scan_info = [
                ['Target:', scan_results.target],
                ['Scan ID:', scan_results.scan_id],
                ['Start Time:', scan_results.start_time.strftime('%Y-%m-%d %H:%M:%S')],
                ['End Time:', scan_results.end_time.strftime('%Y-%m-%d %H:%M:%S')],
                ['Duration:', f"{scan_results.duration:.2f} seconds"]
            ]
            
            info_table = Table(scan_info, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            
            story.append(info_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Statistics
            story.append(Paragraph("Vulnerability Statistics", styles['Heading2']))
            story.append(Spacer(1, 0.1*inch))
            
            stats_data = [
                ['Severity', 'Count'],
                ['Critical', scan_results.statistics.get('critical', 0)],
                ['High', scan_results.statistics.get('high', 0)],
                ['Medium', scan_results.statistics.get('medium', 0)],
                ['Low', scan_results.statistics.get('low', 0)],
                ['Info', scan_results.statistics.get('info', 0)],
                ['Total', scan_results.statistics.get('total', 0)]
            ]
            
            stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4169E1')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(stats_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Charts
            if self.config.include_charts:
                # Severity pie chart
                pie_chart = self.chart_generator.generate_severity_pie_chart(scan_results.statistics)
                if pie_chart:
                    import io
                    img_data = base64.b64decode(pie_chart)
                    img = Image(io.BytesIO(img_data), width=4*inch, height=3*inch)
                    story.append(img)
                    story.append(Spacer(1, 0.2*inch))
            
            # Vulnerabilities
            story.append(PageBreak())
            story.append(Paragraph("Detailed Vulnerabilities", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            for i, vuln in enumerate(scan_results.vulnerabilities[:50], 1):  # Top 50
                story.append(Paragraph(f"{i}. {vuln.get('name', 'Unknown')}", styles['Heading3']))
                story.append(Spacer(1, 0.05*inch))
                
                vuln_details = [
                    ['Severity:', vuln.get('severity', 'Unknown')],
                    ['Category:', vuln.get('category', 'Unknown')],
                    ['URL:', vuln.get('url', 'N/A')],
                    ['CWE:', vuln.get('cwe', 'N/A')],
                ]
                
                vuln_table = Table(vuln_details, colWidths=[1.5*inch, 4.5*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 0.1*inch))
                
                if vuln.get('description'):
                    story.append(Paragraph(f"<b>Description:</b> {vuln['description']}", styles['BodyText']))
                    story.append(Spacer(1, 0.05*inch))
                
                if self.config.include_remediation and vuln.get('remediation'):
                    story.append(Paragraph(f"<b>Remediation:</b> {vuln['remediation']}", styles['BodyText']))
                    story.append(Spacer(1, 0.05*inch))
                
                # Compliance mapping
                if self.config.include_compliance:
                    for framework in self.config.compliance_frameworks:
                        controls = self.compliance_mapper.map_vulnerability(
                            vuln.get('category', ''),
                            framework
                        )
                        if controls:
                            story.append(Paragraph(
                                f"<b>{framework}:</b> {', '.join(controls)}",
                                styles['BodyText']
                            ))
                            story.append(Spacer(1, 0.05*inch))
                
                story.append(Spacer(1, 0.2*inch))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"PDF generation failed: {e}", exc_info=True)
            return False
    
    async def _generate_html(self, scan_results: ScanResults, output_path: Path) -> bool:
        """Generate HTML report"""
        try:
            html_template = """
<!DOCTYPE html>
<html lang="{language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .section {{
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: #f8f9fa;
        }}
        .stat-card.critical {{
            background: #ffebee;
            border-left: 4px solid #c62828;
        }}
        .stat-card.high {{
            background: #ffebee;
            border-left: 4px solid #e53935;
        }}
        .stat-card.medium {{
            background: #fff3e0;
            border-left: 4px solid #fb8c00;
        }}
        .stat-card.low {{
            background: #fff9c4;
            border-left: 4px solid #fbc02d;
        }}
        .stat-card.info {{
            background: #e3f2fd;
            border-left: 4px solid #1976d2;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .vulnerability {{
            border-left: 4px solid #ddd;
            padding: 15px;
            margin: 15px 0;
            background: #fafafa;
            border-radius: 5px;
        }}
        .vulnerability.critical {{
            border-left-color: #c62828;
        }}
        .vulnerability.high {{
            border-left-color: #e53935;
        }}
        .vulnerability.medium {{
            border-left-color: #fb8c00;
        }}
        .vulnerability.low {{
            border-left-color: #fbc02d;
        }}
        .vulnerability h3 {{
            margin-bottom: 10px;
            color: #333;
        }}
        .vulnerability-detail {{
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 10px;
            margin: 5px 0;
        }}
        .vulnerability-detail strong {{
            color: #666;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .badge.critical {{
            background: #c62828;
            color: white;
        }}
        .badge.high {{
            background: #e53935;
            color: white;
        }}
        .badge.medium {{
            background: #fb8c00;
            color: white;
        }}
        .badge.low {{
            background: #fbc02d;
            color: #333;
        }}
        .badge.info {{
            background: #1976d2;
            color: white;
        }}
        .chart-container {{
            margin: 30px 0;
            text-align: center;
        }}
        .chart-container img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <p>{target}</p>
            <p>Generated: {timestamp}</p>
        </header>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{executive_summary}</p>
        </div>
        
        <div class="section">
            <h2>Vulnerability Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="stat-number">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{info}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
            {charts}
        </div>
        
        <div class="section">
            <h2>Detailed Vulnerabilities</h2>
            {vulnerabilities}
        </div>
        
        <footer>
            <p>&copy; 2024 RedSentinel - Professional Security Assessment</p>
            <p>Report ID: {scan_id}</p>
        </footer>
    </div>
</body>
</html>
"""
            
            # Generate vulnerability HTML
            vulns_html = ""
            for vuln in scan_results.vulnerabilities:
                severity = vuln.get('severity', 'info').lower()
                
                vulns_html += f"""
                <div class="vulnerability {severity}">
                    <h3>
                        {vuln.get('name', 'Unknown')}
                        <span class="badge {severity}">{severity.upper()}</span>
                    </h3>
                    <div class="vulnerability-detail">
                        <strong>Category:</strong>
                        <span>{vuln.get('category', 'N/A')}</span>
                    </div>
                    <div class="vulnerability-detail">
                        <strong>URL:</strong>
                        <span>{vuln.get('url', 'N/A')}</span>
                    </div>
                    <div class="vulnerability-detail">
                        <strong>Description:</strong>
                        <span>{vuln.get('description', 'N/A')}</span>
                    </div>
                    <div class="vulnerability-detail">
                        <strong>Remediation:</strong>
                        <span>{vuln.get('remediation', 'N/A')}</span>
                    </div>
                </div>
                """
            
            # Generate charts HTML
            charts_html = ""
            if self.config.include_charts:
                pie_chart = self.chart_generator.generate_severity_pie_chart(scan_results.statistics)
                if pie_chart:
                    charts_html += f"""
                    <div class="chart-container">
                        <img src="data:image/png;base64,{pie_chart}" alt="Severity Distribution">
                    </div>
                    """
            
            # Fill template
            html_content = html_template.format(
                language=self.config.language,
                target=scan_results.target,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                executive_summary=scan_results.executive_summary or "No executive summary provided.",
                critical=scan_results.statistics.get('critical', 0),
                high=scan_results.statistics.get('high', 0),
                medium=scan_results.statistics.get('medium', 0),
                low=scan_results.statistics.get('low', 0),
                info=scan_results.statistics.get('info', 0),
                charts=charts_html,
                vulnerabilities=vulns_html,
                scan_id=scan_results.scan_id
            )
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"HTML generation failed: {e}", exc_info=True)
            return False
    
    async def _generate_json(self, scan_results: ScanResults, output_path: Path) -> bool:
        """Generate JSON report"""
        try:
            report_data = {
                'scan_id': scan_results.scan_id,
                'target': scan_results.target,
                'start_time': scan_results.start_time.isoformat(),
                'end_time': scan_results.end_time.isoformat(),
                'duration': scan_results.duration,
                'statistics': scan_results.statistics,
                'vulnerabilities': scan_results.vulnerabilities,
                'recommendations': scan_results.recommendations,
                'executive_summary': scan_results.executive_summary
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"JSON report generated: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"JSON generation failed: {e}")
            return False
    
    async def _generate_markdown(self, scan_results: ScanResults, output_path: Path) -> bool:
        """Generate Markdown report"""
        try:
            md_content = f"""# Security Assessment Report

## Target: {scan_results.target}

**Scan ID:** {scan_results.scan_id}
**Start Time:** {scan_results.start_time.strftime('%Y-%m-%d %H:%M:%S')}
**End Time:** {scan_results.end_time.strftime('%Y-%m-%d %H:%M:%S')}
**Duration:** {scan_results.duration:.2f} seconds

---

## Executive Summary

{scan_results.executive_summary or "No executive summary provided."}

---

## Vulnerability Statistics

| Severity | Count |
|----------|-------|
| Critical | {scan_results.statistics.get('critical', 0)} |
| High     | {scan_results.statistics.get('high', 0)} |
| Medium   | {scan_results.statistics.get('medium', 0)} |
| Low      | {scan_results.statistics.get('low', 0)} |
| Info     | {scan_results.statistics.get('info', 0)} |
| **Total** | **{scan_results.statistics.get('total', 0)}** |

---

## Detailed Vulnerabilities

"""
            for i, vuln in enumerate(scan_results.vulnerabilities, 1):
                md_content += f"""
### {i}. {vuln.get('name', 'Unknown')}

- **Severity:** {vuln.get('severity', 'Unknown')}
- **Category:** {vuln.get('category', 'Unknown')}
- **URL:** {vuln.get('url', 'N/A')}
- **CWE:** {vuln.get('cwe', 'N/A')}

**Description:**  
{vuln.get('description', 'N/A')}

**Remediation:**  
{vuln.get('remediation', 'N/A')}

---

"""
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
            
            logger.info(f"Markdown report generated: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"Markdown generation failed: {e}")
            return False
    
    async def _generate_xml(self, scan_results: ScanResults, output_path: Path) -> bool:
        """Generate XML report"""
        try:
            import xml.etree.ElementTree as ET
            
            root = ET.Element('security_report')
            
            # Scan info
            scan_info = ET.SubElement(root, 'scan_information')
            ET.SubElement(scan_info, 'scan_id').text = scan_results.scan_id
            ET.SubElement(scan_info, 'target').text = scan_results.target
            ET.SubElement(scan_info, 'start_time').text = scan_results.start_time.isoformat()
            ET.SubElement(scan_info, 'end_time').text = scan_results.end_time.isoformat()
            ET.SubElement(scan_info, 'duration').text = str(scan_results.duration)
            
            # Statistics
            stats = ET.SubElement(root, 'statistics')
            for key, value in scan_results.statistics.items():
                ET.SubElement(stats, key).text = str(value)
            
            # Vulnerabilities
            vulns_elem = ET.SubElement(root, 'vulnerabilities')
            for vuln in scan_results.vulnerabilities:
                vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
                for key, value in vuln.items():
                    ET.SubElement(vuln_elem, key).text = str(value)
            
            # Write
            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)
            tree.write(output_path, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"XML report generated: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"XML generation failed: {e}")
            return False
    
    async def _generate_csv(self, scan_results: ScanResults, output_path: Path) -> bool:
        """Generate CSV report"""
        try:
            import csv
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['name', 'severity', 'category', 'url', 'cwe', 'description', 'remediation']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                for vuln in scan_results.vulnerabilities:
                    row = {key: vuln.get(key, 'N/A') for key in fieldnames}
                    writer.writerow(row)
            
            logger.info(f"CSV report generated: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"CSV generation failed: {e}")
            return False


# Usage example
if __name__ == "__main__":
    async def main():
        # Sample scan results
        scan_results = ScanResults(
            scan_id="scan_20241119_001",
            target="https://example.com",
            start_time=datetime.now(),
            end_time=datetime.now(),
            duration=120.5,
            vulnerabilities=[
                {
                    'name': 'SQL Injection',
                    'severity': 'Critical',
                    'category': 'A03:2021-Injection',
                    'url': 'https://example.com/login',
                    'cwe': 'CWE-89',
                    'description': 'SQL injection vulnerability found',
                    'remediation': 'Use parameterized queries'
                }
            ],
            statistics={
                'critical': 5,
                'high': 12,
                'medium': 25,
                'low': 8,
                'info': 15,
                'total': 65
            },
            recommendations=["Fix SQL injection", "Update security headers"],
            executive_summary="Assessment found 65 vulnerabilities, 5 critical."
        )
        
        # Generate PDF
        config = ReportConfig(format='pdf', template='professional')
        generator = AdvancedReportGenerator(config)
        
        success = await generator.generate_report(scan_results, Path('report.pdf'))
        print(f"PDF generated: {success}")
        
        # Generate HTML
        config_html = ReportConfig(format='html')
        generator_html = AdvancedReportGenerator(config_html)
        
        success_html = await generator_html.generate_report(scan_results, Path('report.html'))
        print(f"HTML generated: {success_html}")
    
    asyncio.run(main())

