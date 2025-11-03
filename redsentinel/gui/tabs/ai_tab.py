#!/usr/bin/env python3
"""
Tab IA & Automation
"""

import customtkinter as ctk
import asyncio
import threading


class AITab:
    """Onglet IA"""
    
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface"""
        # Input
        input_frame = ctk.CTkFrame(self.parent)
        input_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(input_frame, text="Cible:", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
        self.target_entry = ctk.CTkEntry(input_frame, placeholder_text="example.com", width=400)
        self.target_entry.pack(side="left", padx=10)
        
        # Boutons
        buttons_frame = ctk.CTkFrame(self.parent)
        buttons_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.ai_discovery_btn = ctk.CTkButton(buttons_frame, text="AI Discovery", command=self.run_ai_discovery, width=200, height=40)
        self.ai_discovery_btn.pack(side="left", padx=5)
        
        self.recommendations_btn = ctk.CTkButton(buttons_frame, text="Smart Recommendations", command=self.run_recommendations, width=200, height=40)
        self.recommendations_btn.pack(side="left", padx=5)
        
        self.workflows_btn = ctk.CTkButton(buttons_frame, text="Automated Workflows", command=self.run_workflows, width=200, height=40)
        self.workflows_btn.pack(side="left", padx=5)
        
        # Progress
        self.progress_bar = ctk.CTkProgressBar(self.parent)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 10))
        
        # Résultats
        results_frame = ctk.CTkFrame(self.parent)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        self.results_text = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=11, family="Courier"))
        self.results_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    def log(self, msg: str):
        self.results_text.insert("end", msg + "\n")
        self.results_text.see("end")
    
    def _async_wrapper(self, coro_func, *args):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(coro_func(*args))
        finally:
            loop.close()
    
    def run_ai_discovery(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.ai_discovery_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting AI Discovery for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._ai_discovery, target)).start()
    
    def run_recommendations(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.recommendations_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Smart Recommendations for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._recommendations, target)).start()
    
    def run_workflows(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.workflows_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Automated Workflows for {target}...")
        self.log("[*] Workflow: quick")
        threading.Thread(target=self._async_wrapper, args=(self._workflows, target)).start()
    
    async def _ai_discovery(self, target: str):
        try:
            from redsentinel.ai.discovery import automated_discovery_analysis
            target_data = {"subdomains": [], "vulnerabilities": [], "services": [], "open_ports": []}
            results = automated_discovery_analysis(target_data)
            self.progress_bar.set(1.0)
            self.log("[+] AI Discovery complete")
            self.log(str(results) if results else "No results")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.ai_discovery_btn.configure(state="normal")
    
    async def _recommendations(self, target: str):
        try:
            from redsentinel.ai.discovery import SmartRecommendation
            recommender = SmartRecommendation()
            target_data = {"vulnerabilities": [], "services": [], "open_ports": []}
            results = recommender.generate_recommendations(target_data)
            self.progress_bar.set(1.0)
            self.log("[+] Smart Recommendations generated")
            self.log(str(results) if results else "No recommendations")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.recommendations_btn.configure(state="normal")
    
    async def _workflows(self, target: str):
        try:
            from redsentinel.workflows.engine import run_workflow
            results = await run_workflow("quick", [target])
            self.progress_bar.set(1.0)
            self.log("[+] Workflow complete")
            self.log(str(results) if results else "No results")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.workflows_btn.configure(state="normal")
