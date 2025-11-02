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
from redsentinel.reporter import render_report
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
    """Fonction de reconnaissance subdomain"""
    panel = Panel.fit(
        f"[bold]REDSENTINEL > SUBDOMAIN ENUMERATION[/bold]\n\n"
        f"Target: [yellow]{target}[/yellow]",
        border_style="red"
    )
    console.print(panel)
    console.print()
    
    info(f"Starting enumeration for [yellow]{target}[/yellow]...")
    
    # Progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Querying certificate transparency logs...", total=None)
        subs = await crtsh_subdomains(target)
        progress.stop()
    
    console.print()
    success(f"Found {len(subs)} subdomains")
    console.print()
    
    # Display first 50 subdomains
    if subs:
        table_config = get_table_config()
        table = Table(show_header=False, border_style=table_config["border_style"], 
                     box=None, padding=(0, 2))
        table.add_column("Subdomain", style="cyan")
        
        for sub in subs[:50]:
            table.add_row(f"  • {sub}")
        
        console.print(table)
    else:
        warning("No subdomains found")
    
    return subs


async def do_portscan(targets, ports=None):
    """Fonction de scan de ports"""
    ports = ports or [80, 443, 22, 21, 3306, 6379, 8080, 8443]
    results = {}
    
    console.print()
    info(f"Scanning [yellow]{len(targets)}[/yellow] host(s) on [yellow]{len(ports)}[/yellow] port(s)")
    console.print()
    
    # Progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=len(targets))
        
        for h in targets:
            r = await scan_ports(h, ports)
            results[h] = r
            progress.advance(task)
    
    console.print()
    
    # Results table
    table_config = get_table_config()
    table = Table(show_header=True, header_style=table_config["header_style"], 
                  border_style=table_config["border_style"])
    table.add_column("Host", style="cyan", width=30)
    table.add_column("Open Ports", style="green", width=40)
    
    for h in targets:
        open_ports = [str(p) for p, o in results[h].items() if o]
        if open_ports:
            table.add_row(h, ", ".join(open_ports))
        else:
            table.add_row(h, "[dim]None[/dim]")
    
    console.print(table)
    
    total_open = sum(1 for r in results.values() for p, o in r.items() if o)
    console.print()
    success(f"Scan completed: {total_open} open port(s) found")
    
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
    dry_run = cfg.get("execution", {}).get("dry_run", True)
    
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


def interactive_menu():
    """Menu interactif principal"""
    print_banner(show_logo=True)  # Afficher le logo ASCII au-dessus du titre
    
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
        "Select an option to begin:",
        border_style="red"
    ))
    console.print()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    while True:
        console.print()
        # Menu panel
        menu_text = (
            "[bold]Available Commands:[/bold]\n\n"
            "  [cyan][1][/cyan] Subdomain Enumeration (crt.sh)\n"
            "  [cyan][2][/cyan] Quick Port Scan (TCP Connect)\n"
            "  [cyan][3][/cyan] Nmap Scan (Service Detection)\n"
            "  [cyan][4][/cyan] Web HTTP Checks\n"
            "  [cyan][5][/cyan] Generate HTML Report\n"
            "  [red][0][/red] Exit"
        )
        
        console.print(Panel(menu_text, border_style="cyan"))
        console.print()
        
        try:
            choice = Prompt.ask("redsentinel> ", choices=["0", "1", "2", "3", "4", "5"])
        except KeyboardInterrupt:
            console.print()
            console.print()
            info("Exiting...")
            console.print()
            break
        
        if choice == "0":
            console.print()
            info("Goodbye!")
            console.print()
            break
        
        try:
            target = Prompt.ask("Target", default="example.com").strip()
            if not target or target == "":
                error("Target is required")
                continue
            
            if choice == "1":
                console.print()
                loop.run_until_complete(do_recon(target))
                console.print()
            
            elif choice == "2":
                ports_input = Prompt.ask("Ports (comma-separated)", default="80,443,22,8080")
                ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]
                
                console.print()
                info("Fetching subdomains first...")
                subs = loop.run_until_complete(do_recon(target))
                hosts = [target] + subs[:20]
                
                console.print()
                loop.run_until_complete(do_portscan(hosts, ports))
            
            elif choice == "3":
                args_input = Prompt.ask("Nmap args (press Enter for defaults)", default="")
                nmap_args = args_input if args_input else None
                hosts = [target]
                loop.run_until_complete(do_nmap_scan(hosts, nmap_args))
            
            elif choice == "4":
                loop.run_until_complete(do_webchecks([target]))
            
            elif choice == "5":
                console.print()
                info("Generating comprehensive report...")
                console.print()
                
                # Progress for full report
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    progress.add_task("[cyan]Collecting data...", total=None)
                    
                    subs = loop.run_until_complete(do_recon(target))
                    hosts = [target] + subs[:20]
                    ports_res = loop.run_until_complete(do_portscan(hosts))
                    
                    progress.update(progress.task_ids[0], description="[cyan]Fetching web information...")
                    http = loop.run_until_complete(do_webchecks(hosts))
                    
                    progress.update(progress.task_ids[0], description="[cyan]Generating report...")
                    html = render_report(target, subs, ports_res.get(target, {}), http)
                    
                    fn = f"report_{target}.html"
                    with open(fn, "w", encoding="utf-8") as f:
                        f.write(html)
                    
                    progress.stop()
                
                console.print()
                success(f"Report saved to: [cyan]{fn}[/cyan]")
                info(f"Open it in your browser to view the full report")
            
            else:
                error("Invalid choice")
        
        except KeyboardInterrupt:
            console.print()
            warning("Operation cancelled by user")
        
        except Exception as e:
            console.print()
            error(f"Error: {str(e)}")
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
                "  [cyan]-v, --version[/cyan]  Afficher la version\n\n"
                "Launch interactive menu:\n"
                "  [yellow]redsentinel[/yellow]",
                border_style="red"
            ))
            console.print()
            return
    
    interactive_menu()


if __name__ == "__main__":
    main()
