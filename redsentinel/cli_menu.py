#!/usr/bin/env python3
"""
RedSentinel CLI - Interface principale avec design stylé
"""

import asyncio
import sys
import time

from rich.table import Table
from rich.progress import Progress, BarColumn, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt

# Import du design system
from redsentinel.design import (
    console,
    print_banner,
    success,
    error,
    warning,
    info,
    get_table_config,
    get_progress_spinners,
)

from redsentinel.recon import crtsh_subdomains
from redsentinel.scanner import scan_ports
from redsentinel.webcheck import fetch_http_info
from redsentinel.tools.nmap_wrapper import nmap_scan_nm
from redsentinel.tools.nuclei_wrapper import nuclei_scan
from redsentinel.tools.ffuf_wrapper import ffuf_scan, parse_ffuf_json
from redsentinel.tools.dns_tools import comprehensive_dns_enum
from redsentinel.tools.ssl_tools import comprehensive_ssl_analysis
from redsentinel.tools.nikto_wrapper import nikto_scan, parse_nikto_results
from redsentinel.tools.masscan_wrapper import masscan_scan, parse_masscan_json
from redsentinel.tools.cloud_tools import check_s3_bucket, cloudflare_detection, cloud_provider_detection
from redsentinel.tools.cms_scanners import cms_detection, comprehensive_cms_scan
from redsentinel.intel.threat_intel import comprehensive_threat_intel
from redsentinel.intel.correlation import correlate_scan_results
from redsentinel.attacks.password_tools import hydra_scan, medusa_scan, john_hash_crack, hashcat_crack, comprehensive_password_attack
from redsentinel.attacks.exploit_framework import searchsploit_search, suggest_msf_modules, comprehensive_exploit_search
from redsentinel.ai.discovery import automated_discovery_analysis, generate_attack_path, PatternRecognizer, SmartRecommendation, AnomalyDetector
from redsentinel.osint.shodan_client import shodan_search_host, shodan_certificate_search
from redsentinel.osint.censys_client import censys_search_host, censys_certificate_search
from redsentinel.osint.social_engineering import discover_email_patterns, search_github
from redsentinel.vulns.cve_matcher import search_cve, comprehensive_cve_matching
from redsentinel.api.security_testing import comprehensive_api_security_scan, discover_api_endpoints
from redsentinel.manage.target_manager import TargetManager, manage_targets
from redsentinel.monitor.continuous import ContinuousMonitor, run_continuous_check
from redsentinel.workflows.engine import run_workflow, get_available_workflows
from redsentinel.workflows.presets import get_workflow_info
from redsentinel.utils import load_config, now_iso

# Configuration
cfg = load_config()


def format_nmap_results(results):
    """Formate les résultats nmap en tableaux stylés"""
    if not isinstance(results, dict):
        return None
    
    if results.get("dry_run"):
        return results
    
    if "error" in results:
        error(f"Nmap error: {results['error']}")
        return None
    
    formatted_results = []
    
    for host, host_data in results.items():
        if not isinstance(host_data, dict):
            continue
        
        # Tableau principal pour cet host
        table = Table(show_header=True, header_style="bold red", 
                      border_style="cyan", title=f"Host: {host}")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("State", style="green", width=10)
        table.add_column("Service", style="yellow", width=20)
        table.add_column("Version", style="white", width=35)
        
        # Extraire les informations de ports
        protocols = host_data.get("protocols", {})
        all_ports = []
        
        for proto in protocols:
            for port, port_info in protocols[proto].items():
                if isinstance(port_info, dict):
                    state = port_info.get("state", "unknown")
                    name = port_info.get("name", "")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    
                    # Construire la version complète
                    service_name = name if name else "unknown"
                    full_version = f"{product}".strip()
                    if version:
                        full_version += f" {version}".strip()
                    if not full_version:
                        full_version = "-"
                    
                    # Styliser l'état
                    state_style = state.lower()
                    if state_style == "open":
                        state_display = "[green]✓ OPEN[/green]"
                    elif state_style == "filtered":
                        state_display = "[yellow]! FILTERED[/yellow]"
                    elif state_style == "closed":
                        state_display = "[red]✗ CLOSED[/red]"
                    else:
                        state_display = f"[dim]{state}[/dim]"
                    
                    all_ports.append((port, state_display, service_name, full_version))
        
        # Trier par port
        all_ports.sort(key=lambda x: int(x[0]))
        
        # Ajouter les lignes au tableau
        if all_ports:
            for port, state, service, version in all_ports:
                table.add_row(str(port), state, service, version)
            formatted_results.append(table)
        else:
            # Pas de ports ouverts
            table.add_row("-", "[dim]No ports found[/dim]", "-", "-")
            formatted_results.append(table)
    
    return formatted_results


async def do_recon(target):
    """Advanced subdomain enumeration"""
    from redsentinel.tools.recon_advanced import advanced_subdomain_enum
    
    panel = Panel.fit(
        f"[bold]REDSENTINEL > ADVANCED SUBDOMAIN ENUMERATION[/bold]\n\n"
        f"Target: [yellow]{target}[/yellow]\n"
        f"Sources: crt.sh, Certspotter, URLScan",
        border_style="red"
    )
    console.print(panel)
    console.print()
    
    info(f"Starting multi-source enumeration for [yellow]{target}[/yellow]...")
    
    # Progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Querying multiple certificate transparency sources...", total=None)
        results = await advanced_subdomain_enum(target, use_wordlist=False)
        progress.stop()
    
    console.print()
    
    # Display summary
    if results.get("subdomains"):
        success(f"Found {results['total_found']} unique subdomains from multiple sources")
        console.print()
        
        # Source breakdown
        if results.get("sources"):
            table_config = get_table_config()
            source_table = Table(show_header=True, header_style=table_config["header_style"],
                               border_style=table_config["border_style"],
                               title="[bold]Enumeration Sources[/bold]")
            source_table.add_column("Source", style="cyan")
            source_table.add_column("Count", style="green")
            
            for source, count in results["sources"].items():
                source_table.add_row(source, str(count))
            
            console.print(source_table)
            console.print()
        
        # Display subdomains
        table = Table(show_header=False, border_style=table_config["border_style"], 
                     box=None, padding=(0, 2))
        table.add_column("Subdomain", style="cyan")
        
        for sub in results["subdomains"][:50]:
            table.add_row(f"  • {sub}")
        
        console.print(table)
        
        if len(results["subdomains"]) > 50:
            warning(f"Showing first 50 of {len(results['subdomains'])} results")
    else:
        warning("No subdomains found")
    
    return results.get("subdomains", [])


async def do_portscan(targets, ports=None):
    """Professional port scanning with service detection"""
    from redsentinel.tools.recon_advanced import comprehensive_port_scan
    
    # Default to professional top ports if not specified
    ports = ports or [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                      1433, 1723, 3306, 3389, 5432, 5900, 5985, 5986, 8000, 8080, 8443, 9200]
    
    results = {}
    
    console.print()
    info(f"Professional port scanning on [yellow]{len(targets)}[/yellow] host(s)")
    console.print()
    
    # Progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning with service & banner detection...", total=len(targets))
        
        for h in targets:
            r = await comprehensive_port_scan(h, ports=ports, timeout=3.0, concurrency=100)
            results[h] = r
            progress.advance(task)
    
    console.print()
    
    # Results table with details
    table_config = get_table_config()
    for h in targets:
        scan_result = results.get(h, {})
        table = Table(show_header=True, header_style=table_config["header_style"], 
                      border_style=table_config["border_style"],
                      title=f"[bold]Host: {h}[/bold]")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Service", style="yellow", width=20)
        table.add_column("Banner", style="white", width=40)
        
        open_ports = scan_result.get("open_ports", [])
        services = scan_result.get("services", {})
        banners = scan_result.get("banners", {})
        
        if open_ports:
            for port in open_ports:
                service = services.get(port, "Unknown")
                banner = banners.get(port, "")
                banner_short = banner[:35] + "..." if len(banner) > 35 else banner
                table.add_row(str(port), service, banner_short)
        else:
            table.add_row("[dim]None[/dim]", "[dim]No open ports[/dim]", "[dim]-[/dim]")
        
        console.print(table)
        console.print()
        
        # Summary
        if scan_result.get("scan_time"):
            info(f"Scanned {scan_result.get('total_scanned', 0)} ports in {scan_result['scan_time']}")
            console.print()
    
    total_open = sum(len(r.get("open_ports", [])) for r in results.values())
    success(f"Total: {total_open} open port(s) found across all targets")
    
    return results


async def do_webchecks(hosts):
    """Fonction de vérification web"""
    import aiohttp
    
    console.print()
    info(f"Performing HTTP checks on [yellow]{len(hosts)}[/yellow] host(s)")
    console.print()
    
    results = []
    async with aiohttp.ClientSession() as sess:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Fetching HTTP information...", total=len(hosts))
            
            for h in hosts:
                try:
                    url = f"https://{h}"
                    progress.update(task, description=f"[cyan]Checking [yellow]{h}[/yellow]...")
                    r = await fetch_http_info(url, session=sess)
                    results.append(r)
                except Exception:
                    url = f"http://{h}"
                    r = await fetch_http_info(url, session=sess)
                    results.append(r)
                progress.advance(task)
    
    console.print()
    
    # Results table
    table_config = get_table_config()
    table = Table(show_header=True, header_style=table_config["header_style"], 
                  border_style=table_config["border_style"])
    table.add_column("Host", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Server", style="yellow")
    
    for r in results:
        host = r.get('url', 'Unknown')
        status = r.get('status', 'Unknown')
        server = r.get('server', 'Unknown')
        table.add_row(host, str(status), server)
    
    console.print(table)
    
    return results


async def do_nmap_scan(hosts, args=None):
    """Fonction de scan nmap"""
    console.print()
    info(f"Starting Nmap scan on [yellow]{', '.join(hosts)}[/yellow]")
    
    nmap_args = args or cfg.get("tools", {}).get("nmap", {}).get("args", "-sC -sV -T4")
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual Nmap scan")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: [cyan]nmap {nmap_args} {' '.join(hosts)}[/cyan]",
            border_style="yellow"
        ))
        return {"dry_run": True, "hosts": hosts, "args": nmap_args}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running Nmap scan...", total=None)
        res = nmap_scan_nm(hosts, args=nmap_args, dry_run=dry_run)
        progress.stop()
    
    console.print()
    
    # Formater les résultats avec notre fonction de formatage
    formatted = format_nmap_results(res)
    
    if formatted and isinstance(formatted, list):
        # Afficher les tableaux formatés
        for table in formatted:
            console.print(table)
            console.print()
    
    return res


async def do_nuclei_scan(targets, templates=None, severity=None):
    """Fonction de scan Nuclei"""
    console.print()
    info(f"Starting Nuclei vulnerability scan on [yellow]{', '.join(targets)}[/yellow]")
    console.print()
    
    # Vérifier si Nuclei est disponible
    if "error" in (result := nuclei_scan([""], dry_run=True)):
        error("Nuclei not found! Install it with: sudo apt install nuclei")
        console.print()
        info("Or download from: https://github.com/projectdiscovery/nuclei/releases")
        return None
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual Nuclei scan")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: [cyan]nuclei -l targets.txt -silent[/cyan]",
            border_style="yellow"
        ))
        return {"dry_run": True, "targets": targets}
    
    # Construire les arguments
    nuclei_args = "-silent -json"
    if severity:
        nuclei_args += f" -severity {severity}"
    if templates:
        nuclei_args += f" -t {templates}"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running Nuclei scan...", total=None)
        res = nuclei_scan(targets, args=nuclei_args, dry_run=dry_run)
        progress.stop()
    
    console.print()
    
    # Parser et afficher les résultats JSON
    if res.get("rc") == 0 and res.get("out"):
        import json
        vulns = []
        for line in res["out"].strip().split("\n"):
            if line.strip():
                try:
                    vuln = json.loads(line)
                    vulns.append(vuln)
                except json.JSONDecodeError:
                    pass
        
        if vulns:
            # Table des vulnérabilités
            table_config = get_table_config()
            table = Table(show_header=True, header_style=table_config["header_style"],
                         border_style=table_config["border_style"],
                         title="[bold red]Nuclei Vulnerability Scan Results[/bold red]")
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Name", style="cyan", width=40)
            table.add_column("Target", style="yellow", width=30)
            table.add_column("Matched At", style="white")
            
            for vuln in vulns:
                severity = vuln.get("info", {}).get("severity", "unknown").upper()
                name = vuln.get("info", {}).get("name", "Unknown")
                target = vuln.get("host", "Unknown")
                matched = vuln.get("matched-at", "Unknown")
                
                # Colorer selon la sévérité
                if severity == "CRITICAL":
                    severity_colored = f"[bold red]{severity}[/bold red]"
                elif severity == "HIGH":
                    severity_colored = f"[red]{severity}[/red]"
                elif severity == "MEDIUM":
                    severity_colored = f"[yellow]{severity}[/yellow]"
                else:
                    severity_colored = f"[dim]{severity}[/dim]"
                
                table.add_row(severity_colored, name, target, matched)
            
            console.print(table)
            console.print()
            success(f"Found {len(vulns)} vulnerability/vulnerabilities")
        else:
            success("No vulnerabilities found!")
    else:
        if res.get("err"):
            error(f"Nuclei error: {res['err']}")
        else:
            info("Nuclei scan completed")
    
    return res


async def do_ffuf_scan(target_url, wordlist=None, extensions=None):
    """Fonction de directory brute force avec ffuf"""
    console.print()
    info(f"Starting Directory Brute Force on [yellow]{target_url}[/yellow]")
    console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual ffuf scan")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: [cyan]ffuf -u {target_url}/FUZZ -w wordlist.txt[/cyan]",
            border_style="yellow"
        ))
        return {"dry_run": True, "target": target_url}
    
    # Déterminer le wordlist à utiliser
    default_wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Brute forcing directories...", total=None)
        res = ffuf_scan(target_url, wordlist=wordlist or default_wordlist, extensions=extensions)
        progress.stop()
    
    console.print()
    
    # Parser les résultats
    if res.get("rc") == 0:
        results = parse_ffuf_json("/tmp/ffuf_output.json")
        if results:
            table_config = get_table_config()
            table = Table(show_header=True, header_style=table_config["header_style"],
                         border_style=table_config["border_style"],
                         title="[bold green]Directory Brute Force Results[/bold green]")
            table.add_column("Status", style="bold", width=10)
            table.add_column("URL", style="cyan", width=50)
            table.add_column("Size", style="yellow", width=15)
            table.add_column("Words", style="dim", width=10)
            
            for result in results[:50]:  # Afficher les 50 premiers
                status = str(result.get("status", "-"))
                url = result.get("url", "-")
                size = str(result.get("length", "-"))
                words = str(result.get("words", "-"))
                
                # Colorer selon le status code
                if status.startswith("2"):
                    status_colored = f"[green]{status}[/green]"
                elif status.startswith("3"):
                    status_colored = f"[yellow]{status}[/yellow]"
                elif status.startswith("4"):
                    status_colored = f"[red]{status}[/red]"
                else:
                    status_colored = status
                
                table.add_row(status_colored, url, size, words)
            
            console.print(table)
            console.print()
            success(f"Found {len(results)} directory/file(ies)")
        else:
            info("No directories/files found")
    else:
        if res.get("error"):
            error(f"Error: {res['error']}")
        else:
            error("ffuf scan failed")
    
    return res


async def do_dns_enum(domain):
    """Deep DNS analysis for professional reconnaissance"""
    from redsentinel.tools.recon_advanced import deep_dns_analysis
    
    console.print()
    info(f"Starting professional DNS analysis for [yellow]{domain}[/yellow]")
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Deep DNS analysis and security checks...", total=None)
        results = await deep_dns_analysis(domain)
        progress.stop()
    
    console.print()
    
    table_config = get_table_config()
    
    # DNS Records
    if results.get("records"):
        table = Table(show_header=True, header_style=table_config["header_style"],
                     border_style=table_config["border_style"],
                     title="[bold]DNS Records[/bold]")
        table.add_column("Type", style="cyan", width=15)
        table.add_column("Description", style="dim", width=25)
        table.add_column("Values", style="yellow")
        
        for rtype, data in results["records"].items():
            if "values" in data and data["values"]:
                description = data.get("description", "N/A")
                values_str = ", ".join(data["values"][:5])
                if len(data["values"]) > 5:
                    values_str += f" ... (+{len(data['values'])-5} more)"
                table.add_row(rtype, description, values_str)
        
        console.print(table)
        console.print()
    
    # Security Checks
    if results.get("security_checks"):
        security_table = Table(show_header=True, header_style="bold yellow",
                             border_style=table_config["border_style"],
                             title="[bold]Security Findings[/bold]")
        security_table.add_column("Check", style="cyan")
        security_table.add_column("Status", style="green")
        
        for check, status in results["security_checks"].items():
            security_table.add_row(check, status)
        
        console.print(security_table)
        console.print()
    
    success("DNS analysis completed")
    
    return results


async def do_ssl_analysis(host, port=443):
    """Professional SSL/TLS security audit"""
    from redsentinel.tools.recon_advanced import professional_ssl_audit
    
    console.print()
    info(f"Starting professional SSL/TLS audit for [yellow]{host}:{port}[/yellow]")
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Performing comprehensive SSL/TLS analysis...", total=None)
        results = await professional_ssl_audit(host, port)
        progress.stop()
    
    console.print()
    
    if not results.get("error"):
        table_config = get_table_config()
        
        # Overall grade
        grade = results.get("grade", "N/A")
        grade_color = "green" if grade == "A" else "yellow" if grade == "B" else "red"
        console.print(Panel.fit(
            f"[bold]Overall SSL/TLS Grade: [/bold][bold {grade_color}]{grade}[/bold {grade_color}]",
            border_style=table_config["border_style"]
        ))
        console.print()
        
        # Certificate details
        if results.get("certificate"):
            cert = results["certificate"]
            table = Table(show_header=True, header_style=table_config["header_style"],
                         border_style=table_config["border_style"],
                         title="[bold]Certificate Details[/bold]")
            table.add_column("Property", style="cyan", width=20)
            table.add_column("Value", style="yellow")
            
            if cert.get("subject"):
                subject_str = ", ".join([f"{k}={v}" for k, v in cert["subject"].items()])
                table.add_row("Subject", subject_str)
            
            if cert.get("issuer"):
                issuer_str = ", ".join([f"{k}={v}" for k, v in cert["issuer"].items()])
                table.add_row("Issuer", issuer_str)
            
            if cert.get("notAfter"):
                table.add_row("Valid Until", cert["notAfter"])
            
            console.print(table)
            console.print()
        
        # Protocols
        if results.get("protocols"):
            proto_table = Table(show_header=True, header_style=table_config["header_style"],
                               border_style=table_config["border_style"],
                               title="[bold]TLS Protocols[/bold]")
            proto_table.add_column("Property", style="cyan")
            proto_table.add_column("Value", style="yellow")
            
            for proto, value in results["protocols"].items():
                proto_table.add_row(proto, str(value))
            
            console.print(proto_table)
            console.print()
        
        # Vulnerabilities
        if results.get("vulnerabilities"):
            vuln_table = Table(show_header=True, header_style="bold red",
                              border_style=table_config["border_style"],
                              title="[bold red]Security Issues[/bold red]")
            vuln_table.add_column("Vulnerability", style="yellow")
            
            for vuln in results["vulnerabilities"]:
                vuln_table.add_row(vuln)
            
            console.print(vuln_table)
            console.print()
        
        # Recommendations
        if results.get("recommendations"):
            rec_table = Table(show_header=True, header_style="bold green",
                             border_style=table_config["border_style"],
                             title="[bold green]Recommendations[/bold green]")
            rec_table.add_column("Recommendation", style="cyan")
            
            for rec in results["recommendations"]:
                rec_table.add_row(rec)
            
            console.print(rec_table)
            console.print()
        
        success("SSL/TLS audit completed")
    else:
        error_msg = results.get("error", "Unknown error")
        error(f"SSL/TLS audit failed: {error_msg}")
    
    return results


async def do_nikto_scan(target_url):
    """Fonction de scan Nikto"""
    console.print()
    info(f"Starting Nikto web vulnerability scan on [yellow]{target_url}[/yellow]")
    console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual Nikto scan")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: [cyan]nikto -h {target_url}[/cyan]",
            border_style="yellow"
        ))
        return {"dry_run": True, "target": target_url}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running Nikto scan...", total=None)
        res = nikto_scan(target_url, output_format="txt", dry_run=False)
        progress.stop()
    
    console.print()
    
    # Afficher les résultats si disponibles
    if res.get("output_file"):
        results = parse_nikto_results(res["output_file"])
        if results:
            table_config = get_table_config()
            table = Table(show_header=True, header_style=table_config["header_style"],
                         border_style=table_config["border_style"],
                         title="[bold red]Nikto Vulnerability Scan Results[/bold red]")
            table.add_column("Finding", style="cyan", width=60)
            table.add_column("Details", style="yellow")
            
            for finding in results[:50]:  # Afficher les 50 premiers
                finding_text = finding.get("finding", "-")
                details = finding.get("info", "-")
                table.add_row(finding_text, details)
            
            console.print(table)
            console.print()
            success(f"Found {len(results)} finding(s)")
        else:
            info("Reading Nikto output file...")
            try:
                with open(res["output_file"], "r") as f:
                    console.print(Panel.fit(f.read()[:2000], border_style="cyan"))
            except Exception:
                pass
    else:
        if res.get("error"):
            error(f"Error: {res['error']}")
        else:
            info("Nikto scan completed. Check output file for details.")
    
    return res


async def do_workflow(workflow_name, target):
    """Execute a workflow preset"""
    console.print()
    info(f"Starting [yellow]{workflow_name}[/yellow] workflow on [yellow]{target}[/yellow]")
    console.print()
    
    # Get workflow info
    wf_info = get_workflow_info(workflow_name)
    if wf_info:
        console.print(Panel.fit(
            f"[bold]{wf_info['name']}[/bold]\n\n"
            f"{wf_info['description']}\n\n"
            f"Steps: {wf_info['steps']}",
            border_style="cyan"
        ))
        console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual workflow execution")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute workflow: [cyan]{workflow_name}[/cyan]",
            border_style="yellow"
        ))
        return {"dry_run": True, "workflow": workflow_name, "target": target}
    
    # Run workflow
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running workflow...", total=None)
        results = await run_workflow(workflow_name, target)
        progress.stop()
    
    console.print()
    
    # Display results summary
    if results.get("error"):
        error(f"Workflow error: {results['error']}")
    else:
        table_config = get_table_config()
        table = Table(show_header=True, header_style=table_config["header_style"],
                     border_style=table_config["border_style"],
                     title="[bold green]Workflow Execution Summary[/bold green]")
        table.add_column("Step", style="cyan", width=30)
        table.add_column("Status", style="bold", width=15)
        
        for step_result in results.get("steps", []):
            step_name = step_result.get("step", "Unknown")
            status = step_result.get("status", "unknown")
            
            if status == "completed":
                status_colored = "[green]✓ Completed[/green]"
            elif status == "error":
                status_colored = "[red]✗ Error[/red]"
            elif status == "skipped":
                status_colored = "[dim]⊘ Skipped[/dim]"
            else:
                status_colored = f"[yellow]{status}[/yellow]"
            
            table.add_row(step_name, status_colored)
        
        console.print(table)
        console.print()
        
        completed = sum(1 for s in results.get("steps", []) if s.get("status") == "completed")
        total = len(results.get("steps", []))
        success(f"Workflow completed: {completed}/{total} steps successful")
    
    return results


async def do_cms_scan(url):
    """CMS detection and scanning"""
    console.print()
    info(f"Starting CMS detection and scan on [yellow]{url}[/yellow]")
    console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual CMS scan")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: CMS detection and specialized scan",
            border_style="yellow"
        ))
        return {"dry_run": True, "target": url}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Detecting CMS...", total=None)
        results = await comprehensive_cms_scan(url)
        progress.stop()
    
    console.print()
    
    # Display CMS detection
    if results.get("cms_detection"):
        detection = results["cms_detection"]
        if detection.get("cms") != "Unknown":
            table_config = get_table_config()
            table = Table(show_header=True, header_style=table_config["header_style"],
                         border_style=table_config["border_style"],
                         title="[bold green]CMS Detection Results[/bold green]")
            table.add_column("Property", style="cyan", width=20)
            table.add_column("Value", style="yellow")
            
            table.add_row("CMS Type", detection["cms"])
            if detection.get("version"):
                table.add_row("Version", detection["version"])
            table.add_row("Confidence", f"{detection.get('confidence', 0)}%")
            
            console.print(table)
            console.print()
            success("CMS detected!")
        else:
            warning("No CMS detected")
    
    # Display scan results if available
    if results.get("scanner_results") and not results["scanner_results"].get("error"):
        info("Scanner results available in output file")
    
    return results


async def do_cloud_scan(domain):
    """Cloud infrastructure scanning"""
    console.print()
    info(f"Starting cloud infrastructure scan on [yellow]{domain}[/yellow]")
    console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual cloud scan")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: Cloud infrastructure analysis",
            border_style="yellow"
        ))
        return {"dry_run": True, "target": domain}
    
    # Cloudflare detection
    cf_detection = cloudflare_detection(domain)
    
    # Cloud provider detection
    provider_detection = cloud_provider_detection(domain)
    
    table_config = get_table_config()
    table = Table(show_header=True, header_style=table_config["header_style"],
                 border_style=table_config["border_style"],
                 title="[bold blue]Cloud Infrastructure Analysis[/bold blue]")
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="yellow")
    
    table.add_row("Domain", domain)
    if cf_detection.get("behind_cloudflare"):
        table.add_row("Cloudflare", "[green]✓ Yes[/green]")
        if cf_detection.get("ip_info"):
            table.add_row("Cloudflare IP", cf_detection["ip_info"])
    else:
        table.add_row("Cloudflare", "[dim]No[/dim]")
    
    if provider_detection.get("provider") != "Unknown":
        table.add_row("Cloud Provider", provider_detection["provider"])
    if provider_detection.get("ip"):
        table.add_row("IP Address", provider_detection["ip"])
    
    console.print(table)
    console.print()
    success("Cloud infrastructure analysis completed")
    
    return {"cloudflare": cf_detection, "provider": provider_detection}


async def do_threat_intel(ip_or_domain):
    """Threat intelligence gathering"""
    console.print()
    info(f"Gathering threat intelligence for [yellow]{ip_or_domain}[/yellow]")
    console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: threat intelligence requires API keys")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            "Note: Threat intelligence requires API keys\n"
            "Configure in config.yaml or environment variables",
            border_style="yellow"
        ))
        return {"dry_run": True, "target": ip_or_domain}
    
    # Note: This would use API keys from config
    console.print()
    info("Threat intelligence requires API keys (VirusTotal, AbuseIPDB, GreyNoise)")
    info("Check config.yaml for API key configuration")
    warning("Skipping threat intelligence (no API keys configured)")
    
    return None


async def do_data_correlation(target):
    """Data correlation and analysis"""
    console.print()
    info(f"Starting data correlation for [yellow]{target}[/yellow]")
    console.print()
    
    # Example: gather data first
    console.print()
    info("Gathering data from multiple sources...")
    console.print()
    
    # Run subdomain enumeration (using direct function to avoid recursion)
    subs = await crtsh_subdomains(target)
    
    # For demonstration, create simple correlation
    from redsentinel.intel.correlation import DataCorrelation
    
    correlator = DataCorrelation()
    for sub in subs[:50]:
        correlator.add_subdomain(sub)
    
    # Generate correlation report
    report = correlator.generate_report()
    
    console.print()
    console.print(Panel.fit(
        report["report"],
        border_style="green",
        title="[bold]Data Correlation Report[/bold]"
    ))
    
    console.print()
    success("Data correlation completed")
    
    return report


async def do_masscan(host, ports="1-65535"):
    """Ultra-fast port scan with Masscan"""
    console.print()
    info(f"Starting Masscan ultra-fast port scan on [yellow]{host}[/yellow]")
    console.print()
    
    import os
    if os.geteuid() != 0:
        error("Masscan requires root privileges! Run with sudo")
        return None
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual Masscan")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: [cyan]masscan -p{ports} {host}[/cyan]",
            border_style="yellow"
        ))
        return {"dry_run": True, "target": host}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running Masscan...", total=None)
        res = masscan_scan(host, ports=ports)
        progress.stop()
    
    console.print()
    
    if res.get("rc") == 0:
        results = parse_masscan_json("/tmp/masscan_output.json")
        if results:
            table_config = get_table_config()
            table = Table(show_header=True, header_style=table_config["header_style"],
                         border_style=table_config["border_style"],
                         title="[bold magenta]Masscan Results[/bold magenta]")
            table.add_column("IP", style="cyan", width=20)
            table.add_column("Port", style="yellow", width=10)
            table.add_column("Protocol", style="green")
            
            for result in results[:100]:
                ip = result.get("ip", "-")
                port_data = result.get("ports", [{}])[0]
                port = port_data.get("port", "-")
                proto = port_data.get("proto", "-").upper()
                
                table.add_row(ip, str(port), proto)
            
            console.print(table)
            console.print()
            success(f"Found {len(results)} open port(s)")
    else:
        if res.get("error"):
            error(f"Error: {res['error']}")
    
    return res


async def do_password_attack(target, protocol, credentials=None):
    """Password attack with Hydra/Medusa"""
    console.print()
    info(f"Starting password attack on [yellow]{target}[/yellow] ({protocol})")
    console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual password attack")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            "⚠️ Password attacks should only be used with explicit authorization!\n"
            f"Would execute: Hydra/Medusa on {protocol}://{target}",
            border_style="yellow"
        ))
        return {"dry_run": True, "target": target, "protocol": protocol}
    
    # Show warning
    console.print()
    warning("⚠️ WARNING: Password attacks without authorization are ILLEGAL!")
    console.print()
    confirm = Prompt.ask("Continue? (yes/no)", default="no")
    
    if confirm.lower() != "yes":
        info("Operation cancelled")
        return None
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running password attack...", total=None)
        results = comprehensive_password_attack(target, protocol)
        progress.stop()
    
    console.print()
    
    # Display results
    if results.get("hydra") and results["hydra"]:
        console.print()
        success(f"Found {len(results['hydra'])} credential(s)!")
        table_config = get_table_config()
        table = Table(show_header=True, header_style=table_config["header_style"],
                     border_style=table_config["border_style"],
                     title="[bold red]Credential(s) Found[/bold red]")
        table.add_column("Credentials", style="yellow")
        
        for cred in results["hydra"]:
            table.add_row(cred)
        
        console.print(table)
    else:
        info("No credentials found")
    
    return results


async def do_exploit_search(service, version=None):
    """Exploit search and suggestions"""
    console.print()
    info(f"Searching exploits for [yellow]{service}[/yellow]")
    if version:
        info(f"Version: [yellow]{version}[/yellow]")
    console.print()
    
    dry_run = cfg.get("execution", {}).get("dry_run", False)
    
    if dry_run:
        warning("Dry-run mode: skipping actual exploit search")
        console.print()
        console.print(Panel.fit(
            "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
            f"Would execute: searchsploit {service}",
            border_style="yellow"
        ))
        return {"dry_run": True, "service": service}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Searching exploits...", total=None)
        results = comprehensive_exploit_search("", 0, service, version)
        progress.stop()
    
    console.print()
    
    # Display ExploitDB results
    if results.get("exploits", {}).get("searchsploit"):
        exploit_result = results["exploits"]["searchsploit"]
        if exploit_result.get("out"):
            console.print(Panel.fit(
                exploit_result["out"][:2000],
                border_style="red",
                title="[bold]ExploitDB Results[/bold]"
            ))
        console.print()
    
    # Display MSF suggestions
    if results.get("msf_suggestions", {}).get("modules"):
        modules = results["msf_suggestions"]["modules"]
        if modules:
            table_config = get_table_config()
            table = Table(show_header=True, header_style=table_config["header_style"],
                         border_style=table_config["border_style"],
                         title="[bold green]Suggested Metasploit Modules[/bold green]")
            table.add_column("Module", style="cyan", width=40)
            table.add_column("Type", style="yellow", width=15)
            table.add_column("Description", style="white")
            
            for module in modules:
                table.add_row(
                    module.get("name", "-"),
                    module.get("type", "-"),
                    module.get("description", "-")
                )
            
            console.print(table)
            console.print()
    
    return results


async def do_ai_discovery(target):
    """AI-powered automated discovery and recommendations"""
    console.print()
    info(f"Starting AI-powered discovery for [yellow]{target}[/yellow]")
    console.print()
    
    # Gather initial data
    info("Gathering preliminary data...")
    subs = await crtsh_subdomains(target)
    
    # Create target data structure
    target_data = {
        "subdomains": subs,
        "vulnerabilities": [],
        "services": [],
        "open_ports": []
    }
    
    # Run AI analysis
    analysis = automated_discovery_analysis(target_data)
    
    console.print()
    console.print(Panel.fit(
        f"""
[bold]AI Analysis Complete[/bold]

Subdomains analyzed: {len(subs)}
Patterns detected: {len(analysis.get('pattern_analysis', {}))}
Recommendations: {sum(len(v) for v in analysis.get('recommendations', {}).values())}
Anomalies found: {len(analysis.get('anomalies', {}).get('unusual_ports', []))}
Suggested tools: {len(analysis.get('suggested_tools', []))}
""",
        border_style="magenta",
        title="[bold magenta]🧠 AI Discovery Results[/bold magenta]"
    ))
    
    # Show recommendations
    if analysis.get("recommendations"):
        recs = analysis["recommendations"]
        if recs.get("high"):
            console.print()
            console.print("[bold red]High Priority Actions:[/bold red]")
            for rec in recs["high"][:5]:
                console.print(f"  • {rec}")
        
        if recs.get("medium"):
            console.print()
            console.print("[bold yellow]Medium Priority Actions:[/bold yellow]")
            for rec in recs["medium"][:5]:
                console.print(f"  • {rec}")
    
    # Show suggested tools
    if analysis.get("suggested_tools"):
        console.print()
        info("Suggested tools:")
        for tool in analysis["suggested_tools"]:
            console.print(f"  • {tool}")
    
    # Show anomalies
    if analysis.get("anomalies"):
        anomalies = analysis["anomalies"]
        if anomalies.get("unusual_ports"):
            console.print()
            warning("Unusual ports detected:")
            for anomaly in anomalies["unusual_ports"][:5]:
                console.print(f"  • Port {anomaly['port']}: {anomaly['reason']}")
    
    console.print()
    success("AI analysis completed!")
    
    return analysis


async def do_smart_recommendations(target):
    """Smart recommendations based on all findings"""
    console.print()
    info(f"Generating smart recommendations for [yellow]{target}[/yellow]")
    console.print()
    
    # Perform comprehensive analysis
    console.print()
    info("Analyzing target comprehensively...")
    console.print()
    
    # Gather data
    subs = await crtsh_subdomains(target)
    
    # Use AI recommendation engine
    recommender = SmartRecommendation()
    
    findings = {
        "vulnerabilities": [],
        "services": [],
        "open_ports": []
    }
    
    recommendations = recommender.generate_recommendations(findings)
    prioritized = recommender.prioritize_actions(recommendations)
    
    console.print()
    console.print(Panel.fit(
        f"""
[bold]Smart Recommendations[/bold]

Total recommendations: {len(recommendations)}
High priority: {len(prioritized['high'])}
Medium priority: {len(prioritized['medium'])}
Low priority: {len(prioritized['low'])}
""",
        border_style="blue",
        title="[bold blue]💡 Smart Recommendations[/bold blue]"
    ))
    
    # Display prioritized recommendations
    if prioritized.get("high"):
        console.print()
        console.print("[bold red]🔴 HIGH PRIORITY:[/bold red]")
        for i, rec in enumerate(prioritized["high"][:5], 1):
            console.print(f"  {i}. {rec}")
    
    if prioritized.get("medium"):
        console.print()
        console.print("[bold yellow]🟡 MEDIUM PRIORITY:[/bold yellow]")
        for i, rec in enumerate(prioritized["medium"][:5], 1):
            console.print(f"  {i}. {rec}")
    
    console.print()
    success("Smart recommendations generated!")
    
    return prioritized


async def do_osint_comprehensive(target):
    """Comprehensive OSINT gathering"""
    console.print()
    info(f"Starting comprehensive OSINT for [yellow]{target}[/yellow]")
    console.print()
    
    # Note: Requires API keys for full functionality
    console.print(Panel.fit(
        "[yellow]Note:[/yellow] Full OSINT functionality requires API keys\n"
        "(Shodan, Censys, etc.)\n\n"
        "Continuing with available sources...",
        border_style="yellow"
    ))
    console.print()
    
    # Gather basic certificate data (no API key required)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Gathering OSINT data...", total=None)
        
        # Certificate sources
        from redsentinel.recon import crtsh_subdomains
        from redsentinel.osint.cert_sources import all_cert_sources
        subs = await crtsh_subdomains(target)
        
        progress.stop()
    
    console.print()
    success(f"Found {len(subs)} subdomain(s)")
    
    return {"subdomains": subs}


async def do_cve_matching(service_info):
    """Match services to CVEs"""
    console.print()
    info("Starting CVE matching analysis")
    console.print()
    
    if isinstance(service_info, str):
        console.print("Example service info:")
        console.print(Panel.fit(
            '[{"name": "apache", "version": "2.4.49"}, {"name": "mysql", "version": "5.7"}]',
            border_style="cyan"
        ))
        console.print()
        console.print("CVE matching would check for known vulnerabilities...")
        return {"status": "dry_run"}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Matching services to CVEs...", total=None)
        results = await comprehensive_cve_matching(service_info)
        progress.stop()
    
    console.print()
    
    # Display critical CVEs
    if results.get("critical_cves"):
        console.print(Panel.fit(
            f"[bold red]⚠️ {len(results['critical_cves'])} CRITICAL CVEs Found![/bold red]",
            border_style="red"
        ))
        for cve in results["critical_cves"][:5]:
            console.print(f"  • {cve['id']}: {cve['description'][:80]}")
    
    success(f"Found {results['total_cves']} total CVE(s)")
    
    return results


async def do_api_security_scan(url):
    """API security testing"""
    console.print()
    info(f"Starting API security scan on [yellow]{url}[/yellow]")
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning API...", total=None)
        results = await comprehensive_api_security_scan(url)
        progress.stop()
    
    console.print()
    
    # Display vulnerabilities
    if results.get("vulnerabilities"):
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "UNKNOWN")
            console.print(f"[{severity}] {vuln['type']}: {vuln['details']}")
    
    # Display discovered endpoints
    if results.get("endpoints"):
        info(f"Discovered {len(results['endpoints'])} endpoint(s)")
    
    console.print()
    success("API security scan completed")
    
    return results


async def do_target_management():
    """Target management interface"""
    console.print()
    info("Target Management System")
    console.print()
    
    manager = TargetManager()
    stats = manager.get_statistics()
    
    console.print(Panel.fit(
        f"""
[bold]Target Management Stats[/bold]

Total Targets: {stats['total_targets']}
Groups: {stats['total_groups']}
Exclusions: {stats['total_exclusions']}

By Status:
  • New: {stats['targets_by_status']['new']}
  • Scanned: {stats['targets_by_status']['scanned']}
  • Error: {stats['targets_by_status']['error']}
""",
        border_style="blue",
        title="[bold blue]🎯 Target Manager[/bold blue]"
    ))
    
    # Show options
    console.print()
    action = Prompt.ask(
        "Action (add/list/groups/stats)",
        choices=["add", "list", "groups", "stats"],
        default="stats"
    )
    
    if action == "add":
        target_name = Prompt.ask("Target name", default="example.com")
        group_name = Prompt.ask("Group (optional)", default="")
        notes = Prompt.ask("Notes (optional)", default="")
        
        result = manager.add_target(
            target_name,
            group=group_name if group_name else None,
            notes=notes if notes else None
        )
        success(f"Added target: {target_name}")
        
    elif action == "list":
        targets = manager.get_targets()
        if targets:
            for target in targets:
                console.print(f"  • {target['name']} ({target['status']})")
        else:
            info("No targets yet")
    
    return stats


async def do_continuous_monitoring(target):
    """Continuous monitoring"""
    console.print()
    info(f"Setting up continuous monitoring for [yellow]{target}[/yellow]")
    console.print()
    
    monitor = ContinuousMonitor()
    
    console.print(Panel.fit(
        """
[bold]Continuous Monitoring System[/bold]

Monitors targets for:
  • New subdomains
  • New open ports
  • Changed IPs
  • Service changes

Generates alerts on significant changes.
""",
        border_style="magenta",
        title="[bold magenta]🔍 Continuous Monitor[/bold magenta]"
    ))
    
    # Establish baseline
    info("Establishing baseline...")
    baseline_data = {
        "subdomains": [],
        "open_ports": [],
        "services": []
    }
    
    monitor.establish_baseline(target, baseline_data)
    
    console.print()
    success("Baseline established! Monitoring is active.")
    info("Run scans periodically to detect changes")
    
    return {"status": "baseline_established", "target": target}


def interactive_menu():
    """Menu interactif principal"""
    print_banner(show_logo=True)  # Logo + Banner ASCII
    
    # Vérifier les mises à jour disponibles (au démarrage)
    try:
        from redsentinel.version import check_update_and_prompt
        check_update_and_prompt(console)
    except Exception:
        # Si la vérification échoue, continuer silencieusement
        pass
    
    # Welcome panel
    console.print(Panel.fit(
        "[bold red]RedSentinel CLI[/bold red]\n\n"
        "[cyan]Cybersecurity & Pentest Toolkit[/cyan]\n\n"
        "Sélectionnez une option pour commencer:",
        border_style="red"
    ))
    console.print()
    
    # Site web
    console.print(Panel.fit(
        "[bold magenta]Website :[/bold magenta]\n"
        "[bold cyan underline]https://redsentinel.fr[/bold cyan underline]",
        border_style="magenta",
        padding=(0, 3)
    ))
    console.print()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    while True:
        console.print()
        # Menu panel hiérarchique
        menu_text = (
            "[bold]REDSENTINEL v6.0 ULTRA[/bold]\n\n"
            "═══════════════════════════════════════════════════════════\n\n"
            "[bold cyan][1] RECONNAISSANCE & ENUMERATION[/bold cyan]\n"
            "   1.0 FULL PROFESSIONAL RECON PIPELINE (ALL-IN-ONE)\n"
            "   1.1 Subdomain Discovery (Advanced Multi-Source)\n"
            "   1.2 DNS Enumeration Complete\n"
            "   1.3 Quick Port Scan (TCP) + Service Detection\n"
            "   1.4 Nmap Scan (Service Detection)\n"
            "   1.5 Masscan (Ultra-Fast)\n"
            "   1.6 SSL/TLS Analysis\n"
            "   1.7 Cloud Infrastructure Discovery\n\n"
            "[bold yellow][2] VULNERABILITY ANALYSIS[/bold yellow]\n"
            "   2.1 Nuclei Vulnerability Scan\n"
            "   2.2 Nikto Web Scanner\n"
            "   2.3 CVE Matching & Analysis\n"
            "   2.4 CMS Detection & Scan\n"
            "   2.5 Web HTTP Checks\n\n"
            "[bold magenta][3] OSINT & INTELLIGENCE[/bold magenta]\n"
            "   3.1 Complete OSINT Gathering\n"
            "   3.2 Threat Intelligence\n"
            "   3.3 Data Correlation\n\n"
            "[bold red][4] EXPLOITATION & ATTACKS[/bold red]\n"
            "   4.1 Directory Brute Force (ffuf)\n"
            "   4.2 Password Attack (Hydra/Medusa)\n"
            "   4.3 Exploit Search (ExploitDB/MSF)\n"
            "   4.4 API Security Testing\n\n"
            "[bold green][5] AI & AUTOMATION[/bold green]\n"
            "   5.1 AI-Powered Discovery\n"
            "   5.2 Smart Recommendations\n"
            "   5.3 Automated Workflows\n\n"
            "[bold blue][6] MANAGEMENT & MONITORING[/bold blue]\n"
            "   6.1 Target Management\n"
            "   6.2 Continuous Monitoring\n\n"
            "═══════════════════════════════════════════════════════════\n\n"
            "  [red][0][/red] Exit"
        )
        
        console.print(Panel(menu_text, border_style="cyan"))
        console.print()
        
        try:
            choice = Prompt.ask("redsentinel> ")
        except KeyboardInterrupt:
            console.print()
            console.print()
            info("Arrêt en cours...")
            console.print()
            break
        
        if choice == "0":
            console.print()
            info("Au revoir !")
            console.print()
            break
        
        # Routage hiérarchique par catégories
        try:
            # Catégorie 1: RECONNAISSANCE & ÉNUMÉRATION
            if choice == "1.0":
                from redsentinel.tools.recon_pro import full_recon_pipeline
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(full_recon_pipeline(target))
            
            elif choice == "1.1":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_recon(target))
                console.print()
            
            elif choice == "1.2":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_dns_enum(target))
            
            elif choice == "1.3":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                ports_input = Prompt.ask("Ports (séparés par virgule)", default="80,443,22,8080")
                ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]
                console.print()
                info("Récupération des sous-domaines...")
                subs = loop.run_until_complete(do_recon(target))
                hosts = [target] + subs[:20]
                console.print()
                loop.run_until_complete(do_portscan(hosts, ports))
            
            elif choice == "1.4":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                args_input = Prompt.ask("Arguments Nmap (optionnel)", default="")
                nmap_args = args_input if args_input else None
                hosts = [target]
                console.print()
                loop.run_until_complete(do_nmap_scan(hosts, nmap_args))
            
            elif choice == "1.5":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                ports_input = Prompt.ask("Ports (ex: 1-1000)", default="1-65535")
                console.print()
                loop.run_until_complete(do_masscan(target, ports=ports_input))
            
            elif choice == "1.6":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                port_input = Prompt.ask("Port", default="443")
                port = int(port_input) if port_input.isdigit() else 443
                console.print()
                loop.run_until_complete(do_ssl_analysis(target, port))
            
            elif choice == "1.7":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_cloud_scan(target))
            
            # Catégorie 2: ANALYSE DE VULNÉRABILITÉS
            elif choice == "2.1":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                severity_choice = Prompt.ask("Filtre de sévérité (critical,high,medium,low,info) ou all", default="all")
                severity = severity_choice if severity_choice.lower() != "all" else None
                console.print()
                loop.run_until_complete(do_nuclei_scan([target], severity=severity))
            
            elif choice == "2.2":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                url = Prompt.ask("URL cible", default=f"https://{target}")
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                console.print()
                loop.run_until_complete(do_nikto_scan(url))
            
            elif choice == "2.3":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_cve_matching("example"))
            
            elif choice == "2.4":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                url = Prompt.ask("URL cible", default=f"https://{target}")
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                console.print()
                loop.run_until_complete(do_cms_scan(url))
            
            elif choice == "2.5":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_webchecks([target]))
            
            # Catégorie 3: OSINT & INTELLIGENCE
            elif choice == "3.1":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_osint_comprehensive(target))
            
            elif choice == "3.2":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_threat_intel(target))
            
            elif choice == "3.3":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_data_correlation(target))
            
            # Catégorie 4: EXPLOITATION & ATTACKS
            elif choice == "4.1":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                url = Prompt.ask("URL cible", default=f"https://{target}")
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                console.print()
                loop.run_until_complete(do_ffuf_scan(url))
            
            elif choice == "4.2":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                warning("⚠️ UTILISATION AUTORISÉE UNIQUEMENT - ILLÉGAL SANS PERMISSION !")
                console.print()
                protocol = Prompt.ask("Protocole (ssh/ftp/http/smb)", default="ssh")
                console.print()
                loop.run_until_complete(do_password_attack(target, protocol))
            
            elif choice == "4.3":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                service = Prompt.ask("Nom du service (ex: apache, mysql)", default="apache")
                version = Prompt.ask("Version (optionnel)", default="")
                version = version if version else None
                console.print()
                loop.run_until_complete(do_exploit_search(service, version))
            
            elif choice == "4.4":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                url = Prompt.ask("URL de l'API", default=f"https://{target}/api")
                console.print()
                loop.run_until_complete(do_api_security_scan(url))
            
            # Catégorie 5: IA & AUTOMATION
            elif choice == "5.1":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_ai_discovery(target))
            
            elif choice == "5.2":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_smart_recommendations(target))
            
            elif choice == "5.3":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                workflows = get_available_workflows()
                info(f"Workflows disponibles : {', '.join(workflows)}")
                console.print()
                workflow_choice = Prompt.ask("Workflow (quick/standard/deep/vulnerability)", default="quick")
                if workflow_choice in workflows:
                    console.print()
                    loop.run_until_complete(do_workflow(workflow_choice, target))
                else:
                    error(f"Workflow inconnu : {workflow_choice}")
            
            # Catégorie 6: MANAGEMENT & MONITORING
            elif choice == "6.1":
                console.print()
                loop.run_until_complete(do_target_management())
            
            elif choice == "6.2":
                target = Prompt.ask("Cible", default="example.com").strip()
                if not target:
                    error("La cible est requise")
                    continue
                console.print()
                loop.run_until_complete(do_continuous_monitoring(target))
            
            else:
                error("Choix invalide")
        
        except KeyboardInterrupt:
            console.print()
            warning("Opération annulée par l'utilisateur")
        
        except Exception as e:
            console.print()
            error(f"Erreur : {str(e)}")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")


def main():
    """Point d'entrée principal"""
    # Support des arguments de ligne de commande simples
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ["--version", "-v"]:
            try:
                from redsentinel import __version__, get_version_info
                info = get_version_info()
                print(f"RedSentinel v{__version__}")
                if info.get("commit"):
                    print(f"Commit: {info['commit']}")
            except Exception:
                print("RedSentinel v1.0.0")
            return
        elif arg in ["--help", "-h"]:
            print_banner()
            console.print()
            console.print(Panel.fit(
                "[bold red]RedSentinel CLI[/bold red]\n\n"
                "Usage: [cyan]redsentinel[/cyan] [options]\n\n"
                "Options:\n"
                "  [cyan]-h, --help[/cyan]     Afficher cette aide\n"
                "  [cyan]-v, --version[/cyan]  Afficher la version\n"
                "  [cyan]--gui[/cyan]          Lancer l'interface graphique\n\n"
                "Launch interactive menu:\n"
                "  [yellow]redsentinel[/yellow]\n\n"
                "Launch GUI:\n"
                "  [yellow]redsentinel --gui[/yellow]",
                border_style="red"
            ))
            console.print()
            return
        elif arg in ["--gui", "-gui", "gui"]:
            # Lancer l'interface graphique
            try:
                from redsentinel.gui import launch_gui
                launch_gui()
            except ImportError as e:
                console.print()
                error("Impossible de lancer la GUI. Vérifiez que customtkinter est installé:")
                console.print(f"  [cyan]pip install customtkinter[/cyan]")
                console.print()
                console.print(f"Détails: {e}")
            except Exception as e:
                console.print()
                error(f"Erreur lors du lancement de la GUI: {e}")
            return
    
    interactive_menu()


if __name__ == "__main__":
    main()
