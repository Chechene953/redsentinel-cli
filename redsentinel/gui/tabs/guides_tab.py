#!/usr/bin/env python3
"""
Tab Guides & Tutoriels
Interface pour accéder aux guides de pentest
"""

import customtkinter as ctk
from typing import Optional


class GuidesTab:
    """Onglet des guides"""
    
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface"""
        # Header
        header_frame = ctk.CTkFrame(self.parent)
        header_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            header_frame,
            text="Guides de Pentest Professionnels",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(side="left", padx=10, pady=10)
        
        # Catégories
        categories_frame = ctk.CTkFrame(self.parent)
        categories_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkLabel(
            categories_frame,
            text="Sélectionnez une catégorie:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=20, pady=10)
        
        # Boutons de catégories
        buttons_frame = ctk.CTkFrame(self.parent)
        buttons_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkButton(
            buttons_frame,
            text="Vulnérabilités Web",
            command=lambda: self.show_category("web"),
            width=200,
            height=40
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            buttons_frame,
            text="Vulnérabilités Réseau",
            command=lambda: self.show_category("network"),
            width=200,
            height=40
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            buttons_frame,
            text="Vulnérabilités Cloud",
            command=lambda: self.show_category("cloud"),
            width=200,
            height=40
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            buttons_frame,
            text="Privilege Escalation",
            command=lambda: self.show_category("privesc"),
            width=200,
            height=40
        ).pack(side="left", padx=5)
        
        # Recherche
        search_frame = ctk.CTkFrame(self.parent)
        search_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkLabel(
            search_frame,
            text="Recherche:",
            font=ctk.CTkFont(size=12)
        ).pack(side="left", padx=10)
        
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Ex: SQL, XSS, XXE...", width=300)
        self.search_entry.pack(side="left", padx=5)
        
        ctk.CTkButton(
            search_frame,
            text="Rechercher",
            command=self.search_vulns,
            width=100
        ).pack(side="left", padx=5)
        
        # Zone de résultats
        results_frame = ctk.CTkFrame(self.parent)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        ctk.CTkLabel(
            results_frame,
            text="Instructions:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        self.results_text = ctk.CTkTextbox(
            results_frame,
            font=ctk.CTkFont(size=11, family="Courier")
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Instructions initiales
        welcome_text = (
            "Bienvenue dans les Guides de Pentest RedSentinel\n"
            "=" * 80 + "\n\n"
            "Sélectionnez une catégorie ci-dessus pour accéder aux guides détaillés.\n\n"
            "Les guides incluent:\n"
            "  • Descriptions complètes des vulnérabilités\n"
            "  • Étapes détaillées de test\n"
            "  • Commandes d'exemple\n"
            "  • Output attendu\n"
            "  • Recommandations de mitigation\n\n"
            "Utilisez la recherche pour trouver rapidement une vulnérabilité spécifique.\n"
        )
        self.log(welcome_text)
    
    def log(self, message: str):
        """Affiche un message dans les résultats"""
        self.results_text.insert("end", message + "\n")
        self.results_text.see("end")
    
    def show_category(self, category: str):
        """Affiche les vulnérabilités d'une catégorie"""
        self.results_text.delete("1.0", "end")
        
        try:
            from redsentinel.guides.web_vulnerabilities import GUIDES
            
            if category not in GUIDES:
                self.log(f"Catégorie '{category}' introuvable")
                return
            
            cat_data = GUIDES[category]
            
            self.log(f"\n{cat_data['name']}")
            self.log("=" * 80)
            self.log(f"{cat_data['description']}\n")
            
            vulns = cat_data["vulnerabilities"]
            self.log(f"Nombre de vulnérabilités: {len(vulns)}\n")
            self.log("-" * 80 + "\n")
            
            for vuln_id, vuln_data in vulns.items():
                severity_color = (
                    "[RED]" if vuln_data["severity"] == "Critical"
                    else "[YELLOW]" if "High" in vuln_data["severity"]
                    else "[DIM]"
                )
                
                self.log(f"{vuln_data['name']}")
                self.log(f"Sévérité: {vuln_data['severity']}")
                self.log(f"Description: {vuln_data['description']}\n")
                
                if vuln_data.get("steps"):
                    self.log("Tutoriel:")
                    for idx, step in enumerate(vuln_data["steps"], 1):
                        self.log(f"  Étape {idx}: {step['title']}")
                        if step.get("command"):
                            self.log(f"    Commande: {step['command']}")
                        if step.get("expected_output"):
                            self.log(f"    Output: {step['expected_output']}")
                    self.log("")
                
                if vuln_data.get("mitigation"):
                    self.log(f"Mitigation: {vuln_data['mitigation']}\n")
                
                self.log("-" * 80 + "\n")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
    
    def search_vulns(self):
        """Recherche des vulnérabilités"""
        query = self.search_entry.get().strip()
        if not query:
            self.log("Veuillez entrer un terme de recherche")
            return
        
        self.results_text.delete("1.0", "end")
        
        try:
            from redsentinel.guides.web_vulnerabilities import search_vulnerabilities
            
            results = search_vulnerabilities(query)
            
            if not results:
                self.log(f"Aucun résultat pour '{query}'")
                return
            
            self.log(f"Résultats pour '{query}': {len(results)} trouvé(s)\n")
            self.log("=" * 80 + "\n")
            
            for result in results[:20]:
                self.log(f"{result['name']}")
                self.log(f"  Catégorie: {result['category_name']}")
                self.log(f"  ID: {result['category']}:{result['id']}")
                self.log(f"  Sévérité: {result['severity']}\n")
                self.log("-" * 80 + "\n")
            
            if len(results) > 20:
                self.log(f"... et {len(results) - 20} résultat(s) supplémentaire(s)")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())

