#!/usr/bin/env python3
"""
RedSentinel CLI - Professional Command-Line Interface
Main CLI entry point with Click framework
"""

import click
import asyncio
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from redsentinel.design import (
    console, print_banner, success, error, warning, info
)

# Version info
try:
    from redsentinel import __version__
except ImportError:
    __version__ = "6.0.0"


@click.group()
@click.version_option(version=__version__, prog_name="RedSentinel")
@click.pass_context
def cli(ctx):
    """
    🔴 RedSentinel - Professional Cybersecurity Toolkit
    
    Enterprise-grade penetration testing and security assessment platform.
    """
    ctx.ensure_object(dict)


# ===== RECONNAISSANCE COMMANDS =====

@cli.group()
def recon():
    """🔍 Reconnaissance & Enumeration"""
    pass


@recon.command()
@click.argument('target')
@click.option('--deep', is_flag=True, help='Deep reconnaissance with all sources')
@click.option('--wordlist', help='Wordlist for subdomain bruteforce')
@click.option('--output', '-o', help='Output file (JSON)')
def subdomains(target, deep, wordlist, output):
    """Advanced subdomain enumeration"""
    from redsentinel.tools.recon_advanced import advanced_subdomain_enum
    import json
    
    info(f"Starting subdomain enumeration for [yellow]{target}[/yellow]")
    console.print()
    
    async def run():
        results = await advanced_subdomain_enum(
            target, 
            use_wordlist=bool(wordlist),
            wordlist_path=wordlist
        )
        
        if results.get("subdomains"):
            success(f"Found {len(results['subdomains'])} subdomains")
            
            for sub in results['subdomains'][:50]:
                console.print(f"  • {sub}")
            
            if len(results['subdomains']) > 50:
                warning(f"Showing first 50 of {len(results['subdomains'])} results")
            
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
                info(f"Results saved to {output}")
        else:
            warning("No subdomains found")
    
    asyncio.run(run())


@recon.command()
@click.argument('target')
@click.option('--ports', '-p', help='Port range (e.g., 1-1000)', default='1-10000')
@click.option('--top', is_flag=True, help='Scan top 1000 ports')
@click.option('--service-detection', '-sV', is_flag=True, help='Service version detection')
@click.option('--output', '-o', help='Output file (JSON)')
def portscan(target, ports, top, service_detection, output):
    """Professional port scanning with service detection"""
    from redsentinel.tools.recon_advanced import comprehensive_port_scan
    import json
    
    if top:
        port_list = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 
                     993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 5986, 
                     8000, 8080, 8443, 9200]
    else:
        # Parse port range
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, min(end + 1, 65536)))
        else:
            port_list = [int(p.strip()) for p in ports.split(',')]
    
    info(f"Scanning {target} on {len(port_list)} ports...")
    console.print()
    
    async def run():
        results = await comprehensive_port_scan(
            target, 
            ports=port_list,
            timeout=3.0,
            concurrency=100
        )
        
        if results.get('open_ports'):
            success(f"Found {len(results['open_ports'])} open ports")
            
            table = Table(show_header=True, header_style="bold red")
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="yellow")
            table.add_column("Banner", style="white")
            
            for port in results['open_ports']:
                service = results.get('services', {}).get(port, 'Unknown')
                banner = results.get('banners', {}).get(port, '')
                banner_short = banner[:40] + "..." if len(banner) > 40 else banner
                table.add_row(str(port), service, banner_short)
            
            console.print(table)
            
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
                info(f"Results saved to {output}")
        else:
            warning("No open ports found")
    
    asyncio.run(run())


@recon.command()
@click.argument('domain')
@click.option('--output', '-o', help='Output file (JSON)')
def dns(domain, output):
    """Deep DNS analysis and security checks"""
    from redsentinel.tools.recon_advanced import deep_dns_analysis
    import json
    
    info(f"Starting DNS analysis for [yellow]{domain}[/yellow]")
    console.print()
    
    async def run():
        results = await deep_dns_analysis(domain)
        
        # Display DNS records
        if results.get('records'):
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Type", style="cyan")
            table.add_column("Values", style="yellow")
            
            for rtype, data in results['records'].items():
                if data.get('values'):
                    values_str = ", ".join(data['values'][:3])
                    if len(data['values']) > 3:
                        values_str += f" ... (+{len(data['values'])-3} more)"
                    table.add_row(rtype, values_str)
            
            console.print(table)
            console.print()
        
        # Security checks
        if results.get('security_checks'):
            info("Security Analysis:")
            for check, status in results['security_checks'].items():
                console.print(f"  • {check}: {status}")
        
        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            info(f"Results saved to {output}")
        
        success("DNS analysis completed")
    
    asyncio.run(run())


@recon.command()
@click.argument('host')
@click.option('--port', '-p', default=443, help='SSL port (default: 443)')
@click.option('--output', '-o', help='Output file (JSON)')
def ssl(host, port, output):
    """Professional SSL/TLS security audit"""
    from redsentinel.tools.recon_advanced import professional_ssl_audit
    import json
    
    info(f"Starting SSL/TLS audit for [yellow]{host}:{port}[/yellow]")
    console.print()
    
    async def run():
        results = await professional_ssl_audit(host, port)
        
        if not results.get('error'):
            # Overall grade
            grade = results.get('grade', 'N/A')
            grade_color = "green" if grade == "A" else "yellow" if grade == "B" else "red"
            console.print(Panel.fit(
                f"[bold]Overall SSL/TLS Grade: [/bold][bold {grade_color}]{grade}[/bold {grade_color}]",
                border_style="cyan"
            ))
            console.print()
            
            # Certificate info
            if results.get('certificate'):
                cert = results['certificate']
                info(f"Certificate Subject: {cert.get('subject', 'N/A')}")
                info(f"Certificate Issuer: {cert.get('issuer', 'N/A')}")
                info(f"Valid Until: {cert.get('notAfter', 'N/A')}")
                console.print()
            
            # Vulnerabilities
            if results.get('vulnerabilities'):
                warning(f"Found {len(results['vulnerabilities'])} security issues:")
                for vuln in results['vulnerabilities']:
                    console.print(f"  ⚠️  {vuln}")
                console.print()
            
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
                info(f"Results saved to {output}")
            
            success("SSL/TLS audit completed")
        else:
            error(f"SSL/TLS audit failed: {results.get('error')}")
    
    asyncio.run(run())


@recon.command()
@click.argument('target')
@click.option('--full', is_flag=True, help='Full reconnaissance pipeline')
@click.option('--output', '-o', help='Output directory')
def full(target, full, output):
    """Complete reconnaissance pipeline (All-in-One)"""
    from redsentinel.tools.recon_pro import full_recon_pipeline
    
    info(f"Starting [bold]FULL RECONNAISSANCE PIPELINE[/bold] for [yellow]{target}[/yellow]")
    console.print()
    
    asyncio.run(full_recon_pipeline(target))
    
    success("Full reconnaissance completed!")


# ===== VULNERABILITY SCANNING COMMANDS =====

@cli.group()
def vuln():
    """🔎 Vulnerability Analysis"""
    pass


@vuln.command()
@click.argument('target')
@click.option('--severity', '-s', help='Filter by severity (critical,high,medium,low)')
@click.option('--templates', '-t', help='Specific templates to use')
@click.option('--output', '-o', help='Output file')
def nuclei(target, severity, templates, output):
    """Nuclei vulnerability scanning"""
    from redsentinel.tools.nuclei_wrapper import nuclei_scan
    import json
    
    info(f"Starting Nuclei scan on [yellow]{target}[/yellow]")
    console.print()
    
    args = "-silent -json"
    if severity:
        args += f" -severity {severity}"
    if templates:
        args += f" -t {templates}"
    
    results = nuclei_scan([target], args=args)
    
    if results.get('rc') == 0 and results.get('out'):
        vulns = []
        for line in results['out'].strip().split('\n'):
            if line.strip():
                try:
                    vulns.append(json.loads(line))
                except:
                    pass
        
        if vulns:
            success(f"Found {len(vulns)} vulnerabilities")
            
            table = Table(show_header=True, header_style="bold red")
            table.add_column("Severity", style="bold")
            table.add_column("Name", style="cyan")
            table.add_column("Matched At", style="yellow")
            
            for vuln in vulns:
                sev = vuln.get('info', {}).get('severity', 'unknown').upper()
                name = vuln.get('info', {}).get('name', 'Unknown')
                matched = vuln.get('matched-at', 'Unknown')
                
                if sev == 'CRITICAL':
                    sev_colored = f"[bold red]{sev}[/bold red]"
                elif sev == 'HIGH':
                    sev_colored = f"[red]{sev}[/red]"
                elif sev == 'MEDIUM':
                    sev_colored = f"[yellow]{sev}[/yellow]"
                else:
                    sev_colored = f"[dim]{sev}[/dim]"
                
                table.add_row(sev_colored, name, matched)
            
            console.print(table)
            
            if output:
                with open(output, 'w') as f:
                    json.dump(vulns, f, indent=2)
                info(f"Results saved to {output}")
        else:
            success("No vulnerabilities found")
    else:
        if results.get('error'):
            error(f"Nuclei error: {results['error']}")


@vuln.command()
@click.argument('url')
@click.option('--output', '-o', help='Output file')
def nikto(url, output):
    """Nikto web vulnerability scanner"""
    from redsentinel.tools.nikto_wrapper import nikto_scan, parse_nikto_results
    
    info(f"Starting Nikto scan on [yellow]{url}[/yellow]")
    console.print()
    
    results = nikto_scan(url, output_format='txt')
    
    if results.get('output_file'):
        findings = parse_nikto_results(results['output_file'])
        if findings:
            success(f"Found {len(findings)} findings")
            
            for finding in findings[:20]:
                console.print(f"  • {finding.get('finding', 'N/A')}")
            
            if len(findings) > 20:
                warning(f"Showing first 20 of {len(findings)} findings")
        else:
            info("Scan completed, check output file")
    else:
        if results.get('error'):
            error(f"Nikto error: {results['error']}")


@vuln.command()
@click.argument('url')
@click.option('--output', '-o', help='Output file (JSON)')
def cms(url, output):
    """CMS detection and vulnerability scanning"""
    from redsentinel.tools.cms_scanners import comprehensive_cms_scan
    import json
    
    info(f"Starting CMS scan on [yellow]{url}[/yellow]")
    console.print()
    
    async def run():
        results = await comprehensive_cms_scan(url)
        
        if results.get('cms_detection'):
            detection = results['cms_detection']
            if detection.get('cms') != 'Unknown':
                success(f"CMS Detected: {detection['cms']}")
                if detection.get('version'):
                    info(f"Version: {detection['version']}")
                info(f"Confidence: {detection.get('confidence', 0)}%")
                console.print()
            else:
                warning("No CMS detected")
        
        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            info(f"Results saved to {output}")
    
    asyncio.run(run())


@vuln.command()
@click.argument('service')
@click.option('--version', '-v', help='Service version')
@click.option('--output', '-o', help='Output file')
def cve(service, version, output):
    """CVE matching for services"""
    from redsentinel.vulns.cve_matcher import search_cve
    import json
    
    info(f"Searching CVEs for [yellow]{service}[/yellow]")
    if version:
        info(f"Version: [yellow]{version}[/yellow]")
    console.print()
    
    query = f"{service} {version}" if version else service
    results = search_cve(query)
    
    if results:
        success(f"Found {len(results)} CVEs")
        
        table = Table(show_header=True, header_style="bold red")
        table.add_column("CVE ID", style="cyan")
        table.add_column("CVSS", style="yellow")
        table.add_column("Description", style="white")
        
        for cve in results[:20]:
            cve_id = cve.get('id', 'N/A')
            cvss = str(cve.get('cvss', 'N/A'))
            desc = cve.get('description', 'N/A')[:60] + "..."
            table.add_row(cve_id, cvss, desc)
        
        console.print(table)
        
        if len(results) > 20:
            warning(f"Showing first 20 of {len(results)} CVEs")
        
        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            info(f"Results saved to {output}")
    else:
        warning("No CVEs found")


# ===== OSINT COMMANDS =====

@cli.group()
def osint():
    """🕵️ OSINT & Intelligence Gathering"""
    pass


@osint.command()
@click.argument('target')
@click.option('--emails', is_flag=True, help='Harvest emails')
@click.option('--github', is_flag=True, help='Search GitHub')
@click.option('--pastebin', is_flag=True, help='Search Pastebin')
@click.option('--output', '-o', help='Output file (JSON)')
def gather(target, emails, github, pastebin, output):
    """Comprehensive OSINT gathering"""
    import json
    from redsentinel.osint.advanced.email_harvester import EmailHarvester
    from redsentinel.osint.advanced.github_intel import GitHubIntel
    from redsentinel.osint.advanced.pastebin_search import PastebinSearch
    
    info(f"Starting OSINT gathering for [yellow]{target}[/yellow]")
    console.print()
    
    results = {}
    
    async def run():
        if emails:
            info("Harvesting emails...")
            harvester = EmailHarvester()
            email_results = await harvester.harvest_emails(target)
            results['emails'] = email_results
            success(f"Found {len(email_results.get('emails', []))} emails")
            console.print()
        
        if github:
            info("Searching GitHub...")
            gh = GitHubIntel()
            gh_results = await gh.search_organization(target)
            results['github'] = gh_results
            success(f"Found {len(gh_results.get('repositories', []))} repositories")
            console.print()
        
        if pastebin:
            info("Searching Pastebin...")
            pb = PastebinSearch()
            pb_results = await pb.search_domain(target)
            results['pastebin'] = pb_results
            success(f"Found {len(pb_results.get('pastes', []))} pastes")
            console.print()
        
        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            info(f"Results saved to {output}")
    
    asyncio.run(run())


@osint.command()
@click.argument('domain')
@click.option('--output', '-o', help='Output file (JSON)')
def cloud(domain, output):
    """Cloud asset discovery (AWS, Azure, GCP)"""
    from redsentinel.osint.advanced.cloud_assets import CloudAssetDiscovery
    import json
    
    info(f"Starting cloud asset discovery for [yellow]{domain}[/yellow]")
    console.print()
    
    async def run():
        discovery = CloudAssetDiscovery()
        results = await discovery.discover_all(domain)
        
        if results.get('aws'):
            info(f"AWS: Found {len(results['aws'])} assets")
        if results.get('azure'):
            info(f"Azure: Found {len(results['azure'])} assets")
        if results.get('gcp'):
            info(f"GCP: Found {len(results['gcp'])} assets")
        
        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            info(f"Results saved to {output}")
        
        success("Cloud asset discovery completed")
    
    asyncio.run(run())


# ===== EXPLOITATION COMMANDS =====

@cli.group()
def exploit():
    """💣 Exploitation & Attacks (Authorized Use Only!)"""
    pass


@exploit.command()
@click.argument('url')
@click.option('--wordlist', '-w', help='Wordlist path')
@click.option('--extensions', '-e', help='File extensions (comma-separated)')
@click.option('--output', '-o', help='Output file')
def dirbrute(url, wordlist, extensions, output):
    """Directory brute-forcing with ffuf"""
    from redsentinel.tools.ffuf_wrapper import ffuf_scan, parse_ffuf_json
    import json
    
    warning("⚠️ USE ONLY WITH AUTHORIZATION!")
    console.print()
    info(f"Starting directory brute-force on [yellow]{url}[/yellow]")
    console.print()
    
    wordlist = wordlist or "/usr/share/wordlists/dirb/common.txt"
    
    results = ffuf_scan(url, wordlist=wordlist, extensions=extensions)
    
    if results.get('rc') == 0:
        parsed = parse_ffuf_json("/tmp/ffuf_output.json")
        if parsed:
            success(f"Found {len(parsed)} directories/files")
            
            table = Table(show_header=True, header_style="bold green")
            table.add_column("Status", style="bold")
            table.add_column("URL", style="cyan")
            table.add_column("Size", style="yellow")
            
            for result in parsed[:50]:
                status = str(result.get('status', '-'))
                url_path = result.get('url', '-')
                size = str(result.get('length', '-'))
                
                if status.startswith('2'):
                    status_colored = f"[green]{status}[/green]"
                elif status.startswith('3'):
                    status_colored = f"[yellow]{status}[/yellow]"
                else:
                    status_colored = f"[red]{status}[/red]"
                
                table.add_row(status_colored, url_path, size)
            
            console.print(table)
            
            if output:
                with open(output, 'w') as f:
                    json.dump(parsed, f, indent=2)
                info(f"Results saved to {output}")
        else:
            info("No directories/files found")
    else:
        if results.get('error'):
            error(f"Error: {results['error']}")


@exploit.command()
@click.argument('hash_value')
@click.option('--type', '-t', help='Hash type (md5, sha1, sha256, etc.)')
@click.option('--wordlist', '-w', help='Wordlist path')
@click.option('--tool', default='hashcat', help='Tool to use (hashcat/john)')
def hash(hash_value, type, wordlist, tool):
    """Hash cracking with Hashcat/John"""
    from redsentinel.attacks.hash_cracking import crack_hash, detect_hash_type
    
    warning("⚠️ USE ONLY WITH AUTHORIZATION!")
    console.print()
    
    # Auto-detect hash type if not provided
    if not type:
        detected = detect_hash_type(hash_value)
        if detected:
            info(f"Auto-detected hash type: [yellow]{detected}[/yellow]")
            type = detected
    
    info(f"Cracking hash with [yellow]{tool}[/yellow]...")
    console.print()
    
    result = crack_hash(
        hash_value,
        hash_type=type,
        tool=tool,
        wordlist=wordlist,
        use_rockyou=True
    )
    
    if result.get('success'):
        success("✅ PASSWORD FOUND!")
        console.print()
        console.print(Panel.fit(
            f"[bold green]Password: {result.get('password')}[/bold green]\n"
            f"Method: {result.get('method', '').upper()}\n"
            f"Wordlist: {result.get('wordlist', 'N/A')}",
            border_style="green"
        ))
    else:
        warning("❌ Password not found")
        if result.get('error'):
            error(f"Error: {result['error']}")


@exploit.command()
@click.argument('service')
@click.option('--version', '-v', help='Service version')
def search(service, version):
    """Search exploits (ExploitDB/Metasploit)"""
    from redsentinel.attacks.exploit_framework import searchsploit_search, suggest_msf_modules
    
    info(f"Searching exploits for [yellow]{service}[/yellow]")
    if version:
        info(f"Version: [yellow]{version}[/yellow]")
    console.print()
    
    # ExploitDB search
    query = f"{service} {version}" if version else service
    exploitdb_results = searchsploit_search(query)
    
    if exploitdb_results.get('out'):
        console.print(Panel.fit(
            exploitdb_results['out'][:2000],
            title="[bold]ExploitDB Results[/bold]",
            border_style="red"
        ))
        console.print()
    
    # Metasploit suggestions
    msf_results = suggest_msf_modules(service, version or '')
    
    if msf_results.get('modules'):
        info(f"Found {len(msf_results['modules'])} Metasploit modules")
        for module in msf_results['modules'][:10]:
            console.print(f"  • {module.get('name', 'N/A')}")


# ===== REPORTING COMMANDS =====

@cli.group()
def report():
    """📊 Reporting & Documentation"""
    pass


@report.command()
@click.argument('input_file')
@click.option('--format', '-f', type=click.Choice(['html', 'pdf', 'json', 'md']), default='html')
@click.option('--output', '-o', help='Output file')
@click.option('--template', help='Custom template')
def generate(input_file, format, output, template):
    """Generate professional security reports"""
    from redsentinel.reporting.report_generator import ReportGenerator
    import json
    
    info(f"Generating {format.upper()} report from [yellow]{input_file}[/yellow]")
    console.print()
    
    # Load scan data
    with open(input_file, 'r') as f:
        scan_data = json.load(f)
    
    async def run():
        generator = ReportGenerator()
        
        if format == 'html':
            report_content = await generator.generate_html_report(scan_data)
        elif format == 'pdf':
            report_content = await generator.generate_pdf_report(scan_data)
        elif format == 'json':
            report_content = json.dumps(scan_data, indent=2)
        else:  # markdown
            report_content = await generator.generate_markdown_report(scan_data)
        
        # Save report
        output_file = output or f"report.{format}"
        mode = 'wb' if format == 'pdf' else 'w'
        with open(output_file, mode) as f:
            if isinstance(report_content, bytes):
                f.write(report_content)
            else:
                f.write(report_content)
        
        success(f"Report generated: [cyan]{output_file}[/cyan]")
    
    asyncio.run(run())


# ===== WORKFLOW COMMANDS =====

@cli.group()
def workflow():
    """⚙️ Automated Workflows"""
    pass


@workflow.command()
def list():
    """List available workflows"""
    from redsentinel.workflows.presets import get_available_workflows, get_workflow_info
    
    workflows = get_available_workflows()
    
    info(f"Available workflows: {len(workflows)}")
    console.print()
    
    for wf_name in workflows:
        wf_info = get_workflow_info(wf_name)
        if wf_info:
            console.print(f"[bold cyan]{wf_info['name']}[/bold cyan]")
            console.print(f"  {wf_info['description']}")
            console.print(f"  Steps: {wf_info['steps']}")
            console.print()


@workflow.command()
@click.argument('workflow_name')
@click.argument('target')
@click.option('--output', '-o', help='Output directory')
def run(workflow_name, target, output):
    """Run automated workflow"""
    from redsentinel.workflows.engine import run_workflow
    
    info(f"Running workflow [yellow]{workflow_name}[/yellow] on [yellow]{target}[/yellow]")
    console.print()
    
    async def execute():
        results = await run_workflow(workflow_name, target)
        
        if results.get('error'):
            error(f"Workflow error: {results['error']}")
        else:
            completed = sum(1 for s in results.get('steps', []) if s.get('status') == 'completed')
            total = len(results.get('steps', []))
            success(f"Workflow completed: {completed}/{total} steps successful")
    
    asyncio.run(execute())


# ===== DATABASE & WORKSPACE COMMANDS =====

@cli.group()
def workspace():
    """💾 Workspace & Data Management"""
    pass


@workspace.command()
@click.argument('name')
def create(name):
    """Create new workspace"""
    from redsentinel.database.workspace_manager import WorkspaceManager
    
    manager = WorkspaceManager()
    workspace = manager.create_workspace(name)
    
    success(f"Created workspace: [cyan]{name}[/cyan]")
    info(f"Workspace ID: {workspace.id}")


@workspace.command()
def list():
    """List all workspaces"""
    from redsentinel.database.workspace_manager import WorkspaceManager
    
    manager = WorkspaceManager()
    workspaces = manager.list_workspaces()
    
    if workspaces:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Name", style="cyan")
        table.add_column("Created", style="yellow")
        table.add_column("Scans", style="green")
        
        for ws in workspaces:
            table.add_row(
                ws['name'],
                ws['created_at'],
                str(ws.get('scan_count', 0))
            )
        
        console.print(table)
    else:
        info("No workspaces found")


# ===== INTERACTIVE MODE =====

@cli.command()
def interactive():
    """Launch interactive menu (default mode)"""
    from redsentinel.cli_menu import interactive_menu
    interactive_menu()


@cli.command()
def gui():
    """Launch graphical user interface"""
    try:
        from redsentinel.ui.gui_main import launch_gui
        launch_gui()
    except ImportError:
        error("GUI dependencies not installed. Install with: pip install redsentinel[gui]")
    except Exception as e:
        error(f"Failed to launch GUI: {e}")


@cli.command()
def tui():
    """Launch terminal user interface (TUI)"""
    try:
        from redsentinel.ui.tui_dashboard import launch_tui
        asyncio.run(launch_tui())
    except ImportError:
        error("TUI dependencies not installed. Install with: pip install redsentinel[tui]")
    except Exception as e:
        error(f"Failed to launch TUI: {e}")


@cli.command()
def update():
    """Check for updates"""
    from redsentinel.version import check_for_updates
    
    info("Checking for updates...")
    console.print()
    
    update_info = check_for_updates()
    
    if update_info.get('update_available'):
        success(f"Update available: v{update_info['latest_version']}")
        info(f"Current version: v{update_info['current_version']}")
        console.print()
        info("To update, run: pip install --upgrade redsentinel")
    else:
        success("You're running the latest version")


# ===== MAIN ENTRY POINT =====

def main():
    """Main CLI entry point"""
    # If no arguments, launch interactive mode
    if len(sys.argv) == 1:
        from redsentinel.cli_menu import interactive_menu
        interactive_menu()
    else:
        cli()


if __name__ == '__main__':
    main()
