#!/usr/bin/env python3
"""
Tab Management & Monitoring
"""

import customtkinter as ctk
import asyncio
import threading


class ManagementTab:
    """Onglet de gestion"""
    
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
        
        self.target_mgmt_btn = ctk.CTkButton(buttons_frame, text="Target Management", command=self.run_target_mgmt, width=200, height=40)
        self.target_mgmt_btn.pack(side="left", padx=5)
        
        self.monitor_btn = ctk.CTkButton(buttons_frame, text="Continuous Monitoring", command=self.run_monitor, width=200, height=40)
        self.monitor_btn.pack(side="left", padx=5)
        
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
    
    def run_target_mgmt(self):
        self.target_mgmt_btn.configure(state="disabled")
        self.log("[*] Target Management - In development")
        self.progress_bar.set(1.0)
        self.target_mgmt_btn.configure(state="normal")
    
    def run_monitor(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.monitor_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Continuous Monitoring for {target}...")
        self.log("[*] In development")
        self.progress_bar.set(1.0)
        self.monitor_btn.configure(state="normal")
