#!/usr/bin/env python3
"""
RedSentinel CLI - Exemple d'implémentation complète avec design stylé
"""

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich.markup import escape
import click
import time
import sys

console = Console()

# Banner ASCII Art complet
BANNER_ASCII = """
██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██████╔╝█████╗  ██║  ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
██║  ██║███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"""

LOGO_ASCII = """
                                         ,╦@Ñ╦,
                                     ,╔@▓╢╢╢╢╢╢╣@╗,
                                ,╓g╬▓╢╢╢╢╢╩╜╙╩▓╢╢╢╢╢▓N╖,
                        ,╓╓╦@╬▓╢╢╢╢╢╢▓╩╜        ╙╩▓╢╢╢╢╢╢╣▓@g╦╓,,
                 ╒╬▓╣╢╢╢╢╢╢╢╢╢╢╢▓╩╙`                 ╙╨╬╣╢╢╢╢╢╢╢╢╢╢╢▓▓╗
                 ╟╢╢╢╣▓▓╩╩╜╙`                              `╙╙╨╩╬▓╣╢╢╢╣
                 ╟╢╢╢[                                            ]╢╢╢╣
                 ╟╢╢╢[                                            ]╢╢╢╣
                 ╟╢╢╢[                                            ]╢╢╢╣
                 ╟╢╢╢[                                            ]╢╢╢╣
                 ╟╢╢╢[                                            ]╢╢╢╣
                 ╟╢╢╢[                                            ]╢╢╢╣
                 ╟╢╢╢[                                            ]╢╢╢╣
                 ]╢╢╢▌                                            ▐╢╢╢▌
                  ╢╢╢╣                                            ▓╢╢╢C
                  ╟╢╢╢@                                          ╔╢╢╢▓
                   ▓╢╢╢╕                                        ,╣╢╢╢`
                    ╣╢╢╢╕                                      ,▓╢╢╢╛
                     ▓╢╢╢╗                                    ╓╣╢╢╢╛
                      ╫╢╢╢▓,                                 ╬╢╢╢▓
                       ╙╣╢╢╢N                              g▓╢╢╢╝
                         ╚╢╢╢╢N                          g▓╢╢╢▓
                           ╨╢╢╢╢@,                    ,@╣╢╢╢▓`
                             ╚▓╢╢╢▓╦,              ,╦▓╢╢╢╢╝²
                               ╙╬╢╢╢╢▓N,        ,g▓╢╢╢╢▓╜
                                  ╙╬╢╢╢╢╢@╦,,╥@▓╢╢╢╢▓╜
                                     "╩▓╢╢╢╢╢╢╢╢╢╩╙
                                         ╙╩▓╢Ñ╜

"""

def print_banner():
    """Affiche le banner RedSentinel avec ASCII art complet"""
    # Affichage direct de l'ASCII art sans Panel pour éviter le troncage
    console.print("\n", end="")
    console.print(BANNER_ASCII.strip(), style="bold red")
    console.print("\n[bold red]🔴 CYBERSECURITY | PENTEST | RED TEAM TOOLKIT[/bold red]\n")


def success(msg: str):
    """Affiche un message de succès"""
    console.print(f"[bold green][✓][/bold green] [green]{msg}[/green]")


def error(msg: str):
    """Affiche un message d'erreur"""
    console.print(f"[bold red][✗][/bold red] [red]{msg}[/red]")


def warning(msg: str):
    """Affiche un message d'avertissement"""
    console.print(f"[bold yellow][!][/bold yellow] [yellow]{msg}[/yellow]")


def info(msg: str):
    """Affiche un message d'information"""
    console.print(f"[bold cyan][>][/bold cyan] [cyan]{msg}[/cyan]")


def debug(msg: str):
    """Affiche un message de debug"""
    console.print(f"[dim][DEBUG][/dim] [dim]{msg}[/dim]")


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version="1.0.0", prog_name="RedSentinel CLI")
def cli(ctx):
    """RedSentinel - Cybersecurity & Pentest Toolkit"""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(Panel.fit(
            "[bold red]RedSentinel CLI[/bold red]\n\n"
            "Use [cyan]--help[/cyan] to see available commands.",
            border_style="red"
        ))


@cli.command()
@click.option("-t", "--target", required=True, help="Target host or IP")
@click.option("-p", "--ports", default="1-1000", help="Port range (e.g., 1-1000 or 80,443,8080)")
@click.option("-T", "--threads", default=50, type=int, help="Number of threads")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--timeout", default=3, type=int, help="Connection timeout in seconds")
def scan(target: str, ports: str, threads: int, verbose: bool, timeout: int):
    """Perform port scanning on target host"""
    print_banner()
    
    info(f"Target: [yellow]{target}[/yellow]")
    info(f"Port Range: [yellow]{ports}[/yellow]")
    info(f"Threads: [yellow]{threads}[/yellow]")
    info(f"Timeout: [yellow]{timeout}s[/yellow]")
    console.print()
    
    # Simulate scanning with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=100)
        
        # Simulate scan progress
        for i in range(100):
            time.sleep(0.02)
            progress.update(task, advance=1)
    
    console.print()
    
    # Results table
    table = Table(show_header=True, header_style="bold red", border_style="cyan")
    table.add_column("Port", style="cyan", width=8)
    table.add_column("Status", style="green", width=12)
    table.add_column("Service", style="yellow", width=15)
    table.add_column("Banner", style="white")
    
    # Example results
    table.add_row("80", "[green]✓ OPEN[/green]", "HTTP", "Apache/2.4.41")
    table.add_row("443", "[green]✓ OPEN[/green]", "HTTPS", "Apache/2.4.41")
    table.add_row("8080", "[green]✓ OPEN[/green]", "HTTP-PROXY", "Squid/4.10")
    table.add_row("22", "[red]✗ FILTERED[/red]", "SSH", "No response")
    table.add_row("3306", "[yellow]! FILTERED[/yellow]", "MySQL", "Filtered by firewall")
    
    console.print(table)
    console.print()
    success("Scan completed: 3 ports open, 2 filtered")
    info("Duration: 12.3s")


@cli.command()
@click.option("-t", "--target", required=True, help="Target domain")
@click.option("-w", "--wordlist", help="Wordlist file path")
@click.option("-e", "--engines", multiple=True, default=["passive", "dns"], 
              help="Enumeration engines (passive, active, dns, certificate)")
@click.option("-o", "--output", help="Output file path")
def enum(target: str, wordlist: str, engines: tuple, output: str):
    """Subdomain enumeration"""
    print_banner()
    
    panel = Panel.fit(
        f"[bold]REDSENTINEL > SUBDOMAIN ENUMERATION[/bold]\n\n"
        f"Target: [yellow]{target}[/yellow]\n"
        f"Engines: [cyan]{', '.join(engines)}[/cyan]",
        border_style="red"
    )
    console.print(panel)
    console.print()
    
    if wordlist:
        info(f"Wordlist: [yellow]{wordlist}[/yellow]")
    if output:
        info(f"Output: [yellow]{output}[/yellow]")
    console.print()
    
    # Progress with enumeration
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Enumerating subdomains...", total=100)
        
        for i in range(100):
            time.sleep(0.03)
            if i % 10 == 0:
                progress.update(task, description=f"[cyan]Found: {i//10 + 3} subdomains...")
            progress.update(task, advance=1)
    
    console.print()
    
    # Results
    results = [
        ("api.example.com", "200 OK"),
        ("admin.example.com", "403 Forbidden"),
        ("dev.example.com", "200 OK"),
        ("mail.example.com", "301 Redirect"),
        ("ftp.example.com", "220 FTP Ready"),
    ]
    
    table = Table(show_header=True, header_style="bold red", border_style="cyan")
    table.add_column("Subdomain", style="cyan")
    table.add_column("Status", style="green")
    
    for subdomain, status in results:
        table.add_row(subdomain, status)
    
    console.print(table)
    console.print()
    success(f"Enumeration completed: {len(results)} subdomains found")
    info("Duration: 45.2s")
    
    if output:
        success(f"Results saved to: {output}")


@cli.command()
@click.option("-t", "--target", required=True, help="Target URL")
@click.option("--profile", default="owasp", type=click.Choice(["owasp", "quick", "full"]), 
              help="Scan profile")
@click.option("-o", "--output", help="Report output file")
def vuln(target: str, profile: str, output: str):
    """Vulnerability scanning"""
    print_banner()
    
    console.print(Panel.fit(
        f"[bold red]REDSENTINEL > VULNERABILITY SCAN[/bold red]\n\n"
        f"Target: [yellow]{target}[/yellow]\n"
        f"Profile: [cyan]{profile.upper()}[/cyan]",
        border_style="red"
    ))
    console.print()
    
    info("Initializing scan...")
    time.sleep(0.5)
    success("Target is reachable")
    info("Detected: Apache/2.4.41, PHP/7.4.3")
    info("Testing 150+ attack vectors...")
    console.print()
    
    # Simulate vulnerability detection
    time.sleep(1)
    
    # Vulnerabilities table
    vuln_table = Table(show_header=True, header_style="bold red", border_style="yellow")
    vuln_table.add_column("Severity", style="bold", width=10)
    vuln_table.add_column("Vulnerability", style="cyan")
    vuln_table.add_column("Location", style="white")
    vuln_table.add_column("CVSS", style="yellow")
    
    vuln_table.add_row(
        "[bold red]HIGH[/bold red]",
        "SQL Injection",
        "/api/users?id=",
        "9.8"
    )
    vuln_table.add_row(
        "[bold yellow]MEDIUM[/bold yellow]",
        "XSS (Reflected)",
        "/search?q=",
        "6.1"
    )
    vuln_table.add_row(
        "[dim]LOW[/dim]",
        "Missing Security Headers",
        "All pages",
        "3.1"
    )
    
    console.print(vuln_table)
    console.print()
    
    # Summary panel
    summary = Panel.fit(
        "[bold]Summary[/bold]\n\n"
        "Critical: [red]0[/red]\n"
        "High:     [red]1[/red]\n"
        "Medium:   [yellow]1[/yellow]\n"
        "Low:      [dim]3[/dim]\n"
        "Info:     [cyan]12[/cyan]",
        border_style="cyan"
    )
    console.print(summary)
    console.print()
    
    success("Scan completed")
    if output:
        info(f"Report: {output}")
    else:
        info("Report: reports/vuln_scan_2025-01-XX.html")


if __name__ == "__main__":
    cli()

