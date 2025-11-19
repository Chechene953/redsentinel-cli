#!/usr/bin/env python3
"""
RedSentinel System Check
Verifies all dependencies and system requirements
"""

import sys
import subprocess
import importlib
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    required = (3, 8)
    
    if version >= required:
        return True, f"Python {version.major}.{version.minor}.{version.micro}"
    else:
        return False, f"Python {version.major}.{version.minor}.{version.micro} (Required: 3.8+)"


def check_python_packages():
    """Check required Python packages"""
    packages = {
        'click': 'Click',
        'rich': 'Rich',
        'aiohttp': 'aiohttp',
        'asyncio': 'asyncio',
        'sqlalchemy': 'SQLAlchemy',
        'cryptography': 'Cryptography',
        'beautifulsoup4': 'BeautifulSoup4',
        'requests': 'Requests',
        'dnspython': 'dnspython',
        'python-nmap': 'python-nmap',
        'scapy': 'Scapy',
        'jinja2': 'Jinja2',
        'pyyaml': 'PyYAML',
    }
    
    results = {}
    
    for package, display_name in packages.items():
        try:
            if package == 'beautifulsoup4':
                importlib.import_module('bs4')
            else:
                importlib.import_module(package.replace('-', '_'))
            results[display_name] = (True, "Installed")
        except ImportError:
            results[display_name] = (False, "Not installed")
    
    return results


def check_optional_packages():
    """Check optional Python packages"""
    packages = {
        'psycopg2': 'PostgreSQL (psycopg2)',
        'redis': 'Redis',
        'matplotlib': 'Matplotlib',
        'numpy': 'NumPy',
        'pandas': 'Pandas',
        'scikit-learn': 'scikit-learn',
        'PyQt6': 'PyQt6 (GUI)',
        'textual': 'Textual (TUI)',
    }
    
    results = {}
    
    for package, display_name in packages.items():
        try:
            importlib.import_module(package.replace('-', '_'))
            results[display_name] = (True, "Installed")
        except ImportError:
            results[display_name] = (False, "Optional")
    
    return results


def check_external_tools():
    """Check external security tools"""
    tools = {
        'nmap': 'Nmap',
        'nikto': 'Nikto',
        'nuclei': 'Nuclei',
        'ffuf': 'ffuf',
        'masscan': 'Masscan',
        'sqlmap': 'SQLMap',
        'hydra': 'Hydra',
        'john': 'John the Ripper',
        'hashcat': 'Hashcat',
        'gobuster': 'Gobuster',
        'wpscan': 'WPScan',
        'searchsploit': 'SearchSploit',
        'msfconsole': 'Metasploit',
    }
    
    results = {}
    
    for cmd, display_name in tools.items():
        try:
            # Check if command exists
            if sys.platform == 'win32':
                result = subprocess.run(['where', cmd], capture_output=True, timeout=2)
            else:
                result = subprocess.run(['which', cmd], capture_output=True, timeout=2)
            
            if result.returncode == 0:
                # Try to get version
                try:
                    version_result = subprocess.run([cmd, '--version'], 
                                                   capture_output=True, 
                                                   timeout=2, 
                                                   text=True)
                    version_line = version_result.stdout.split('\n')[0][:40]
                    results[display_name] = (True, version_line)
                except:
                    results[display_name] = (True, "Installed")
            else:
                results[display_name] = (False, "Not found")
        except Exception:
            results[display_name] = (False, "Not found")
    
    return results


def check_redsentinel_modules():
    """Check RedSentinel modules"""
    modules = [
        ('redsentinel.cli_main', 'CLI Main'),
        ('redsentinel.scanner', 'Scanner'),
        ('redsentinel.recon', 'Recon'),
        ('redsentinel.core.event_bus', 'Event Bus'),
        ('redsentinel.core.plugin_manager', 'Plugin Manager'),
        ('redsentinel.database.engine', 'Database Engine'),
        ('redsentinel.database.workspace_manager', 'Workspace Manager'),
        ('redsentinel.osint.advanced.email_harvester', 'Email Harvester'),
        ('redsentinel.tools.recon_advanced', 'Advanced Recon'),
        ('redsentinel.performance.connection_pool', 'Connection Pool'),
        ('redsentinel.reporting.report_generator', 'Report Generator'),
        ('redsentinel.utils.error_handler', 'Error Handler'),
    ]
    
    results = {}
    
    for module_name, display_name in modules:
        try:
            importlib.import_module(module_name)
            results[display_name] = (True, "OK")
        except ImportError as e:
            results[display_name] = (False, f"Import error: {str(e)[:30]}")
        except Exception as e:
            results[display_name] = (False, f"Error: {str(e)[:30]}")
    
    return results


def display_results(title, results):
    """Display results in a table"""
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Component", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="dim")
    
    for name, (status, details) in results.items():
        status_icon = "✅" if status else "❌"
        status_text = f"{status_icon} {'OK' if status else 'Missing'}"
        
        if status:
            status_style = "[green]"
        else:
            status_style = "[red]"
        
        table.add_row(
            name,
            f"{status_style}{status_text}[/{status_style.strip('[')]",
            details
        )
    
    console.print(Panel(table, title=f"[bold]{title}[/bold]", border_style="cyan"))
    console.print()


def main():
    """Run system check"""
    console.print("\n[bold cyan]🔍 RedSentinel System Check[/bold cyan]\n")
    
    # Python Version
    py_ok, py_info = check_python_version()
    if py_ok:
        console.print(f"[green]✅ {py_info}[/green]\n")
    else:
        console.print(f"[red]❌ {py_info}[/red]\n")
        return 1
    
    # Check Python packages
    console.print("[bold]Checking Python Packages...[/bold]")
    packages = check_python_packages()
    display_results("Required Python Packages", packages)
    
    # Check optional packages
    console.print("[bold]Checking Optional Packages...[/bold]")
    optional = check_optional_packages()
    display_results("Optional Python Packages", optional)
    
    # Check external tools
    console.print("[bold]Checking External Security Tools...[/bold]")
    tools = check_external_tools()
    display_results("External Security Tools", tools)
    
    # Check RedSentinel modules
    console.print("[bold]Checking RedSentinel Modules...[/bold]")
    modules = check_redsentinel_modules()
    display_results("RedSentinel Modules", modules)
    
    # Summary
    total_required = len(packages)
    installed_required = sum(1 for status, _ in packages.values() if status)
    
    total_tools = len(tools)
    installed_tools = sum(1 for status, _ in tools.values() if status)
    
    total_modules = len(modules)
    working_modules = sum(1 for status, _ in modules.values() if status)
    
    console.print(Panel.fit(
        f"[bold]System Check Summary[/bold]\n\n"
        f"Python Packages: {installed_required}/{total_required} required packages installed\n"
        f"External Tools: {installed_tools}/{total_tools} tools found\n"
        f"RedSentinel Modules: {working_modules}/{total_modules} modules working\n\n"
        f"Overall Status: {'[green]READY[/green]' if installed_required == total_required and working_modules == total_modules else '[yellow]PARTIALLY READY[/yellow]'}",
        border_style="green" if installed_required == total_required and working_modules == total_modules else "yellow"
    ))
    
    # Recommendations
    if installed_required < total_required:
        console.print("\n[bold yellow]⚠️  Recommendations:[/bold yellow]")
        console.print("  • Install missing Python packages: pip install -r requirements.txt")
    
    if installed_tools < 5:
        console.print("  • Install external security tools for full functionality")
        console.print("  • See INSTALLATION_STEPS.md for tool installation guides")
    
    if working_modules < total_modules:
        console.print("  • Some RedSentinel modules have errors")
        console.print("  • Run: python test_cli.py --imports-only for detailed diagnostics")
    
    console.print()
    
    return 0 if (installed_required == total_required and working_modules == total_modules) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)
