#!/usr/bin/env python3
"""
RedSentinel GUI - Fenêtre principale
Interface graphique moderne avec CustomTkinter
"""

import customtkinter as ctk
from .tabs.recon_tab import ReconTab
from .tabs.vuln_tab import VulnTab
from .tabs.osint_tab import OSINTTab
from .tabs.attacks_tab import AttacksTab
from .tabs.ai_tab import AITab
from .tabs.management_tab import ManagementTab

# Configuration CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class RedSentinelGUI(ctk.CTk):
    """Fenêtre principale de RedSentinel"""
    
    def __init__(self):
        super().__init__()
        
        # Configuration de la fenêtre
        self.title("RedSentinel v6.0 ULTRA")
        self.geometry("1400x900")
        self.minsize(1200, 700)
        
        # Colors RedSentinel
        self.colors = {
            "primary": "#DC143C",
            "secondary": "#FF6347",
            "accent": "#00CED1",
            "success": "#32CD32",
            "warning": "#FFD700",
            "error": "#FF0000"
        }
        
        # Créer le header
        self.create_header()
        
        # Créer les tabs
        self.create_tabs()
        
        # Créer le footer
        self.create_footer()
    
    def create_header(self):
        """Crée l'en-tête de l'application"""
        header_frame = ctk.CTkFrame(self, height=80, corner_radius=0)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Logo et titre
        title = ctk.CTkLabel(
            header_frame,
            text="REDSENTINEL v6.0 ULTRA",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(side="left", padx=30, pady=20)
        
        # Lien du site web
        website_btn = ctk.CTkButton(
            header_frame,
            text="redsentinel.fr",
            fg_color="transparent",
            border_width=2,
            width=150,
            command=lambda: self.open_website()
        )
        website_btn.pack(side="right", padx=30, pady=20)
    
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
            ("Management", ManagementTab)
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

