#!/usr/bin/env python3
"""
Tab OSINT & Intelligence
"""

import customtkinter as ctk
import asyncio
import threading


class OSINTTab:
    """Onglet OSINT"""
    
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
        
        self.osint_btn = ctk.CTkButton(buttons_frame, text="Complete OSINT", command=self.run_osint, width=200, height=40)
        self.osint_btn.pack(side="left", padx=5)
        
        self.threat_btn = ctk.CTkButton(buttons_frame, text="Threat Intelligence", command=self.run_threat, width=200, height=40)
        self.threat_btn.pack(side="left", padx=5)
        
        self.correlation_btn = ctk.CTkButton(buttons_frame, text="Data Correlation", command=self.run_correlation, width=200, height=40)
        self.correlation_btn.pack(side="left", padx=5)
        
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
    
    def run_osint(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.osint_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting OSINT gathering for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._osint_scan, target)).start()
    
    def run_threat(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.threat_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Threat intelligence for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._threat_scan, target)).start()
    
    def run_correlation(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.correlation_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Data correlation for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._correlation_scan, target)).start()
    
    async def _osint_scan(self, target: str):
        try:
            from redsentinel.osint.social_engineering import discover_email_patterns
            self.log("[*] Discovering email patterns...")
            results = await discover_email_patterns(target)
            self.log(str(results) if results else "No results")
            self.progress_bar.set(1.0)
            self.log("[+] OSINT gathering complete")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.osint_btn.configure(state="normal")
    
    async def _threat_scan(self, target: str):
        try:
            from redsentinel.intel.threat_intel import comprehensive_threat_intel
            results = await comprehensive_threat_intel(target)
            self.progress_bar.set(1.0)
            self.log("[+] Threat intelligence complete")
            self.log(str(results) if results else "No results")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.threat_btn.configure(state="normal")
    
    async def _correlation_scan(self, target: str):
        try:
            from redsentinel.intel.correlation import correlate_scan_results
            results = await correlate_scan_results([target])
            self.progress_bar.set(1.0)
            self.log("[+] Data correlation complete")
            self.log(str(results) if results else "No results")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.correlation_btn.configure(state="normal")
