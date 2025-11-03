#!/usr/bin/env python3
"""
Visualiseur de guides en ligne de commande
Interface interactive pour consulter les guides de pentest
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.markdown import Markdown
from rich.syntax import Syntax
from typing import Dict, List

from redsentinel.design import console, success, error, info, warning, get_table_config
from .web_vulnerabilities import GUIDES, get_all_categories, get_vulnerability_details


def display_category_menu():
    """Affiche le menu des catégories"""
    table_config = get_table_config()
    
    table = Table(show_header=True, header_style=table_config["header_style"],
                 border_style=table_config["border_style"],
                 title="[bold]Catégories de Vulnérabilités[/bold]")
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Catégorie", style="yellow", width=30)
    table.add_column("Description", style="white", width=50)
    
    for cat_id, cat_data in GUIDES.items():
        table.add_row(
            cat_id,
            cat_data["name"],
            cat_data["description"]
        )
    
    console.print()
    console.print(table)
    console.print()


def display_vulnerabilities_in_category(category: str):
    """Affiche les vulnérabilités d'une catégorie"""
    if category not in GUIDES:
        error(f"Catégorie '{category}' introuvable")
        return
    
    cat_data = GUIDES[category]
    table_config = get_table_config()
    
    table = Table(show_header=True, header_style=table_config["header_style"],
                 border_style=table_config["border_style"],
                 title=f"[bold]{cat_data['name']}[/bold]")
    table.add_column("N°", style="cyan", width=5)
    table.add_column("Vulnérabilité", style="yellow", width=40)
    table.add_column("Sévérité", style="red", width=15)
    
    for idx, (vuln_id, vuln_data) in enumerate(cat_data["vulnerabilities"].items(), 1):
        # Colorer selon la sévérité
        severity_color = "red" if vuln_data["severity"] == "Critical" else "yellow" if "High" in vuln_data["severity"] else "dim"
        severity = f"[{severity_color}]{vuln_data['severity']}[/{severity_color}]"
        
        table.add_row(str(idx), vuln_data["name"], severity)
    
    console.print()
    console.print(table)
    console.print()


def display_vulnerability_tutorial(category: str, vuln_id: str):
    """Affiche le tutoriel complet d'une vulnérabilité"""
    vuln = get_vulnerability_details(category, vuln_id)
    
    if not vuln:
        error("Vulnérabilité introuvable")
        return
    
    console.print()
    
    # En-tête
    severity_color = "red" if vuln["severity"] == "Critical" else "yellow" if "High" in vuln["severity"] else "dim"
    header_panel = Panel.fit(
        f"[bold]{vuln['name']}[/bold]\n"
        f"[{severity_color}]Sévérité: {vuln['severity']}[/{severity_color}]",
        border_style="cyan"
    )
    console.print(header_panel)
    console.print()
    
    # Description
    console.print(Panel(
        f"[bold]Description:[/bold]\n{vuln['description']}",
        border_style="dim",
        title=""
    ))
    console.print()
    
    # Étapes du tutoriel
    console.print("[bold cyan]Tutoriel de test:[/bold cyan]")
    console.print()
    
    for idx, step in enumerate(vuln["steps"], 1):
        console.print(f"[bold yellow]Étape {idx}: {step['title']}[/bold yellow]")
        console.print(f"  [dim]{step['description']}[/dim]")
        console.print()
        
        # Commande
        if step.get("command"):
            console.print("[bold green]Commande:[/bold green]")
            console.print(Syntax(step["command"], "bash", theme="monokai", line_numbers=False))
            console.print()
        
        # Output attendu
        if step.get("expected_output"):
            console.print("[bold magenta]Output attendu:[/bold magenta]")
            console.print(Panel(
                step["expected_output"],
                border_style="magenta",
                padding=(0, 2)
            ))
            console.print()
        
        console.print("-" * 80)
        console.print()
    
    # Mitigation
    if vuln.get("mitigation"):
        console.print("[bold green]Mitigation recommandée:[/bold green]")
        mitigation_panel = Panel(
            vuln["mitigation"],
            border_style="green",
            title=""
        )
        console.print(mitigation_panel)
        console.print()


def interactive_guides_menu():
    """Menu interactif pour naviguer dans les guides"""
    console.print()
    console.print(Panel.fit(
        "[bold]REDSENTINEL - GUIDES DE PENTEST[/bold]\n\n"
        "Tutoriels complets pour tester des vulnérabilités",
        border_style="red"
    ))
    console.print()
    
    while True:
        # Afficher les catégories
        display_category_menu()
        
        # Choix de la catégorie
        choice = Prompt.ask(
            "[cyan]Choisir une catégorie (ID ou 0 pour quitter)[/cyan]",
            default="web"
        )
        
        if choice == "0":
            break
        
        if choice not in GUIDES:
            error(f"Catégorie '{choice}' invalide")
            continue
        
        # Afficher les vulnérabilités de la catégorie
        display_vulnerabilities_in_category(choice)
        
        # Choisir une vulnérabilité
        console.print(f"[dim]Vulnérabilités disponibles: {', '.join(GUIDES[choice]['vulnerabilities'].keys())}[/dim]")
        vuln_choice = Prompt.ask(
            "[cyan]Choisir une vulnérabilité (ID ou retour)[/cyan]"
        )
        
        if vuln_choice.lower() == "retour":
            continue
        
        if vuln_choice not in GUIDES[choice]["vulnerabilities"]:
            error(f"Vulnérabilité '{vuln_choice}' invalide")
            continue
        
        # Afficher le tutoriel
        display_vulnerability_tutorial(choice, vuln_choice)
        
        # Continuer ?
        continue_choice = Prompt.ask(
            "[cyan]Continuer dans cette catégorie ? (o/N)[/cyan]",
            default="N"
        )
        
        if continue_choice.lower() != "o":
            continue


def quick_search_menu():
    """Menu de recherche rapide"""
    console.print()
    console.print("[bold cyan]Recherche de vulnérabilités[/bold cyan]")
    console.print()
    
    from redsentinel.guides.web_vulnerabilities import search_vulnerabilities
    
    query = Prompt.ask("[cyan]Mot-clé de recherche[/cyan]")
    
    if not query:
        return
    
    results = search_vulnerabilities(query)
    
    if not results:
        warning(f"Aucun résultat pour '{query}'")
        return
    
    table_config = get_table_config()
    table = Table(show_header=True, header_style=table_config["header_style"],
                 border_style=table_config["border_style"],
                 title=f"[bold]Résultats pour '{query}'[/bold]")
    table.add_column("Catégorie", style="cyan")
    table.add_column("Vulnérabilité", style="yellow")
    table.add_column("Sévérité", style="red")
    
    for result in results[:20]:  # Limiter à 20 résultats
        severity_color = "red" if result["severity"] == "Critical" else "yellow" if "High" in result["severity"] else "dim"
        severity = f"[{severity_color}]{result['severity']}[/{severity_color}]"
        
        table.add_row(result["category_name"], result["name"], severity)
    
    console.print()
    console.print(table)
    console.print()
    
    if results:
        choice = Prompt.ask("[cyan]Afficher un tutoriel ? (ID catégorie:vuln ou 0)[/cyan]", default="0")
        
        if choice != "0" and ":" in choice:
            cat, vuln = choice.split(":", 1)
            display_vulnerability_tutorial(cat, vuln)


def guides_menu():
    """Menu principal des guides"""
    while True:
        console.print()
        menu_panel = Panel(
            "[bold]GUIDES DE PENTEST[/bold]\n\n"
            "[cyan]1.[/cyan] Parcourir par catégorie\n"
            "[cyan]2.[/cyan] Rechercher une vulnérabilité\n"
            "[cyan]3.[/cyan] Afficher toutes les catégories\n"
            "[red]0.[/red] Retour",
            border_style="cyan"
        )
        console.print(menu_panel)
        console.print()
        
        choice = Prompt.ask("[cyan]Choix[/cyan]", default="0")
        
        if choice == "0":
            break
        elif choice == "1":
            interactive_guides_menu()
        elif choice == "2":
            quick_search_menu()
        elif choice == "3":
            display_category_menu()
        else:
            error("Choix invalide")

