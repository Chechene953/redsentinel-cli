#!/usr/bin/env python3
"""
RedSentinel GUI - Fenêtre principale
Interface graphique moderne avec CustomTkinter
"""

import customtkinter as ctk
import json
import os
from pathlib import Path
from .tabs.recon_tab import ReconTab
from .tabs.vuln_tab import VulnTab
from .tabs.osint_tab import OSINTTab
from .tabs.attacks_tab import AttacksTab
from .tabs.ai_tab import AITab
from .tabs.management_tab import ManagementTab
from .tabs.guides_tab import GuidesTab

# Configuration CustomTkinter
ctk.set_appearance_mode("dark")

# Charger les design tokens
def load_design_tokens():
    """Charge les tokens de design depuis design_tokens.json"""
    tokens_path = Path(__file__).parent.parent / "design_tokens.json"
    try:
        with open(tokens_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None

DESIGN_TOKENS = load_design_tokens()

# Configuration du thème par défaut
ctk.set_default_color_theme("blue")


class RedSentinelGUI(ctk.CTk):
    """Fenêtre principale de RedSentinel"""
    
    def __init__(self):
        super().__init__()
        
        # Configuration de la fenêtre
        self.title("RedSentinel v6.0 ULTRA")
        self.geometry("1400x900")
        self.minsize(1200, 700)
        
        # Charger le favicon
        self.load_favicon()
        
        # Colors RedSentinel depuis design tokens
        if DESIGN_TOKENS:
            self.colors = {
                "primary": DESIGN_TOKENS["colors"]["red"]["primary"],
                "secondary": DESIGN_TOKENS["colors"]["red"]["bright"],
                "accent": DESIGN_TOKENS["colors"]["accent"]["cyan"],
                "success": DESIGN_TOKENS["colors"]["accent"]["green"],
                "warning": DESIGN_TOKENS["colors"]["accent"]["yellow"],
                "error": "#FF0000"
            }
        else:
            self.colors = {
                "primary": "#E11D47",
                "secondary": "#FF3366",
                "accent": "#06B6D4",
                "success": "#10B981",
                "warning": "#F59E0B",
                "error": "#FF0000"
            }
        
        # Créer le header
        self.create_header()
        
        # Créer les tabs
        self.create_tabs()
        
        # Créer le footer
        self.create_footer()
    
    def load_favicon(self):
        """Charge le favicon de l'application"""
        assets_dir = Path(__file__).parent.parent
        favicon_path = assets_dir / "favicon.ico"
        if favicon_path.exists():
            try:
                # Pour Windows
                if os.name == 'nt':
                    self.iconbitmap(str(favicon_path))
            except Exception:
                pass
    
    def create_header(self):
        """Crée l'en-tête de l'application avec branding RedSentinel"""
        # Couleurs depuis design tokens
        header_bg = DESIGN_TOKENS["colors"]["black"]["deep"] if DESIGN_TOKENS else "#0A0A0A"
        primary_color = DESIGN_TOKENS["colors"]["red"]["primary"] if DESIGN_TOKENS else "#E11D47"
        accent_color = DESIGN_TOKENS["colors"]["accent"]["cyan"] if DESIGN_TOKENS else "#06B6D4"
        
        header_frame = ctk.CTkFrame(
            self, 
            height=90,
            corner_radius=0,
            fg_color=header_bg,
            bg_color=header_bg
        )
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Title avec la police personnalisée
        font_family = DESIGN_TOKENS["fonts"]["title"][0] if DESIGN_TOKENS else "Arial"
        title = ctk.CTkLabel(
            header_frame,
            text="REDSENTINEL v6.0 ULTRA",
            font=ctk.CTkFont(
                size=32, 
                weight="bold",
                family=font_family
            ),
            text_color=primary_color
        )
        title.pack(side="left", padx=30, pady=25)
        
        # Sous-titre
        subtitle = ctk.CTkLabel(
            header_frame,
            text="Cybersecurity & Pentest Toolkit",
            font=ctk.CTkFont(size=12),
            text_color=accent_color
        )
        subtitle.pack(side="left", padx=(0, 20))
        
        # Lien du site web avec style personnalisé
        website_btn = ctk.CTkButton(
            header_frame,
            text="https://redsentinel.fr",
            fg_color="transparent",
            border_width=2,
            border_color=accent_color,
            text_color=accent_color,
            width=180,
            height=35,
            command=lambda: self.open_website()
        )
        website_btn.pack(side="right", padx=30, pady=25)
    
    def create_tabs(self):
        """Crée les onglets par catégorie"""
        # Tabview principal
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Ajouter tous les tabs
        tabs = [
            ("Reconnaissance", ReconTab),
            ("Vulnerabilities", VulnTab),
            ("OSINT & Intelligence", OSINTTab),
            ("Exploitation & Attacks", AttacksTab),
            ("AI & Automation", AITab),
            ("Management", ManagementTab),
            ("Guides", GuidesTab)
        ]
        
        self.tab_instances = {}
        for tab_name, tab_class in tabs:
            tab = self.tabview.add(tab_name)
            self.tab_instances[tab_name] = tab_class(tab)
    
    def create_footer(self):
        """Crée le pied de page"""
        footer_frame = ctk.CTkFrame(self, height=50, corner_radius=0)
        footer_frame.pack(fill="x", padx=0, pady=0)
        footer_frame.pack_propagate(False)
        
        # Status
        self.status_label = ctk.CTkLabel(
            footer_frame,
            text="Prêt",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="left", padx=20, pady=10)
        
        # Copyright
        copyright_label = ctk.CTkLabel(
            footer_frame,
            text="© 2025 Redsentinel - https://redsentinel.fr",
            font=ctk.CTkFont(size=12)
        )
        copyright_label.pack(side="right", padx=20, pady=10)
    
    def open_website(self):
        """Ouvre le site web dans le navigateur"""
        import webbrowser
        webbrowser.open("https://redsentinel.fr")
    
    def update_status(self, message):
        """Met à jour le message de statut"""
        self.status_label.configure(text=message)


if __name__ == "__main__":
    app = RedSentinelGUI()
    app.mainloop()

