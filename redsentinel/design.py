#!/usr/bin/env python3
"""
RedSentinel Design System
Charge les design tokens et fournit les helpers de style
"""

import json
import os
from pathlib import Path
from rich.console import Console
from rich.align import Align
from rich import box

# Chemin vers le fichier de design tokens
TOKENS_FILE = Path(__file__).parent / "design_tokens.json"

# Console Rich globale configurée avec les couleurs du design system
console = Console(style=None)


class DesignSystem:
    """Système de design RedSentinel basé sur les tokens JSON"""
    
    def __init__(self, tokens_file: Path = None):
        self.tokens_file = tokens_file or TOKENS_FILE
        self.tokens = self._load_tokens()
        self._setup_rich_console()
    
    def _load_tokens(self) -> dict:
        """Charge les design tokens depuis le JSON"""
        try:
            with open(self.tokens_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: Design tokens file not found at {self.tokens_file}")
            return {}
    
    def _setup_rich_console(self):
        """Configure la console Rich avec les couleurs du design system"""
        # Rich utilise des noms de style natifs
        # On configure les couleurs pour qu'elles correspondent aux tokens
        pass
    
    @property
    def colors(self) -> dict:
        """Retourne la palette de couleurs"""
        return self.tokens.get("colors", {})
    
    @property
    def icons(self) -> dict:
        """Retourne les icônes"""
        return self.tokens.get("icons", {})
    
    @property
    def banners(self) -> dict:
        """Retourne les bannières"""
        return self.tokens.get("banners", {})
    
    @property
    def messages(self) -> dict:
        """Retourne les formats de messages"""
        return self.tokens.get("messages", {})
    
    @property
    def progress(self) -> dict:
        """Retourne les tokens de progression"""
        return self.tokens.get("progress", {})
    
    @property
    def tables(self) -> dict:
        """Retourne les tokens de tableaux"""
        return self.tokens.get("tables", {})
    
    @property
    def layouts(self) -> dict:
        """Retourne les tokens de layout"""
        return self.tokens.get("layouts", {})


# Instance globale du design system
design = DesignSystem()


# Banners
def get_banner(banner_type: str = "main", force_compact: bool = False) -> str:
    """
    Récupère un banner par son type
    
    Args:
        banner_type: Type de banner (main, compact, minimal)
        force_compact: Force l'utilisation du banner compact si terminal trop étroit
    """
    banners = design.banners
    
    # Si force_compact est True ou terminal trop petit, utiliser le banner compact
    if force_compact or (banner_type == "main" and console.width < 80):
        banner_text = banners.get("compact", banners.get("main", ""))
    else:
        banner_text = banners.get(banner_type, banners.get("main", ""))
    
    # Convertir les \n échappés en vrais retours à la ligne
    return banner_text.replace("\\n", "\n")


# Icônes
ICON_SUCCESS = design.icons.get("success", "✓")
ICON_ERROR = design.icons.get("error", "✗")
ICON_WARNING = design.icons.get("warning", "!")
ICON_INFO = design.icons.get("info", ">")
ICON_DEBUG = design.icons.get("debug", "🔍")


# Messages helpers avec Rich
def success(msg: str):
    """Affiche un message de succès"""
    icon = ICON_SUCCESS
    console.print(f"[bold green][{icon}][/bold green] [green]{msg}[/green]")


def error(msg: str):
    """Affiche un message d'erreur"""
    icon = ICON_ERROR
    console.print(f"[bold red][{icon}][/bold red] [red]{msg}[/red]")


def warning(msg: str):
    """Affiche un message d'avertissement"""
    icon = ICON_WARNING
    console.print(f"[bold yellow][{icon}][/bold yellow] [yellow]{msg}[/yellow]")


def info(msg: str):
    """Affiche un message d'information"""
    icon = ICON_INFO
    console.print(f"[bold cyan][{icon}][/bold cyan] [cyan]{msg}[/cyan]")


def debug(msg: str):
    """Affiche un message de debug"""
    console.print(f"[dim][DEBUG][/dim] [dim]{msg}[/dim]")


# Print banner
def print_banner(banner_type: str = "main"):
    """Affiche le banner RedSentinel centré avec bordure ASCII"""
    from rich.text import Text
    from rich.panel import Panel
    
    console.print("\n")
    
    # Créer le banner complet
    banner = get_banner(banner_type)
    banner_lines = banner.strip().split('\n')
    
    # Ajouter le sous-titre si main banner
    if banner_type == "main":
        subtitle = design.banners.get("main_subtitle", "🔴 CYBERSECURITY | PENTEST | RED TEAM TOOLKIT")
        banner_lines.append("")
        banner_lines.append(subtitle)
    
    # Reconstruire le banner avec toutes les lignes
    full_banner = "\n".join(banner_lines)
    
    # Centrer avec Rich et ajouter une bordure style cyberpunk
    if banner_type == "main":
        # Utiliser Panel pour une bordure stylée
        panel = Panel(
            Text(full_banner, style="bold red"),
            border_style="bold red",
            box=box.HEAVY,
            padding=(1, 2),
            expand=False
        )
        centered_panel = Align.center(panel)
        console.print(centered_panel)
    else:
        # Pour les autres bannières, affichage simple
        for line in banner_lines:
            console.print(Text(line, style="bold red"))
    
    console.print()


# Table configuration
def get_table_config():
    """Retourne la configuration des tableaux"""
    tables = design.tables
    return {
        "border_style": tables.get("border_style", "cyan"),
        "header_style": tables.get("header_style", "bold red"),
    }


# Progress configuration
def get_progress_spinners():
    """Retourne les spinners de progression"""
    return design.progress.get("spinners", ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])


# Layout configuration
def get_prompt():
    """Retourne le prompt par défaut"""
    return design.layouts.get("prompt", "redsentinel> ")


# Colors access
def get_color(name: str) -> str:
    """Récupère une couleur par son nom (ex: 'red.primary')"""
    parts = name.split(".")
    value = design.colors
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


# Export important components
__all__ = [
    "console",
    "design",
    "get_banner",
    "print_banner",
    "success",
    "error",
    "warning",
    "info",
    "debug",
    "get_table_config",
    "get_progress_spinners",
    "get_prompt",
    "get_color",
    "ICON_SUCCESS",
    "ICON_ERROR",
    "ICON_WARNING",
    "ICON_INFO",
    "ICON_DEBUG",
]

