#!/usr/bin/env python3
"""
Tab d'Analyse de Vulnérabilités
"""

import customtkinter as ctk
import asyncio
import threading


class VulnTab:
    """Onglet d'analyse de vulnérabilités"""
    
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
        
        self.nuclei_btn = ctk.CTkButton(buttons_frame, text="Nuclei Scan", command=self.run_nuclei, width=200, height=40)
        self.nuclei_btn.pack(side="left", padx=5)
        
        self.nikto_btn = ctk.CTkButton(buttons_frame, text="Nikto Scanner", command=self.run_nikto, width=200, height=40)
        self.nikto_btn.pack(side="left", padx=5)
        
        self.cve_btn = ctk.CTkButton(buttons_frame, text="CVE Matching", command=self.run_cve, width=200, height=40)
        self.cve_btn.pack(side="left", padx=5)
        
        # Deuxième ligne
        buttons_frame2 = ctk.CTkFrame(self.parent)
        buttons_frame2.pack(fill="x", padx=20, pady=(0, 20))
        
        self.cms_btn = ctk.CTkButton(buttons_frame2, text="CMS Detection", command=self.run_cms, width=200, height=40)
        self.cms_btn.pack(side="left", padx=5)
        
        self.webcheck_btn = ctk.CTkButton(buttons_frame2, text="Web HTTP Checks", command=self.run_webcheck, width=200, height=40)
        self.webcheck_btn.pack(side="left", padx=5)
        
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
    
    def run_nuclei(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.nuclei_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Nuclei scan for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._nuclei_scan, target)).start()
    
    def run_nikto(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.nikto_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Nikto scan for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._nikto_scan, target)).start()
    
    def run_cve(self):
        self.log("[*] CVE Matching - In development")
    
    def run_cms(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.cms_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting CMS detection for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._cms_scan, target)).start()
    
    def run_webcheck(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.webcheck_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Web HTTP checks for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._webcheck, target)).start()
    
    async def _nuclei_scan(self, target: str):
        try:
            from redsentinel.tools.nuclei_wrapper import nuclei_scan
            results = await nuclei_scan([target])
            self.progress_bar.set(1.0)
            self.log("[+] Nuclei scan complete")
            self.log(str(results) if results else "No vulnerabilities found")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.nuclei_btn.configure(state="normal")
    
    async def _nikto_scan(self, target: str):
        try:
            url = f"https://{target}" if not target.startswith(("http://", "https://")) else target
            from redsentinel.tools.nikto_wrapper import nikto_scan
            results = await nikto_scan(url)
            self.progress_bar.set(1.0)
            self.log("[+] Nikto scan complete")
            self.log(str(results) if results else "No issues found")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.nikto_btn.configure(state="normal")
    
    async def _cms_scan(self, target: str):
        try:
            url = f"https://{target}" if not target.startswith(("http://", "https://")) else target
            from redsentinel.tools.cms_scanners import comprehensive_cms_scan
            results = await comprehensive_cms_scan(url)
            self.progress_bar.set(1.0)
            self.log("[+] CMS detection complete")
            self.log(str(results) if results else "No CMS detected")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.cms_btn.configure(state="normal")
    
    async def _webcheck(self, target: str):
        try:
            from redsentinel.webcheck import fetch_http_info
            results = await fetch_http_info(f"https://{target}")
            self.progress_bar.set(1.0)
            self.log("[+] Web HTTP checks complete")
            self.log(str(results) if results else "No results")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.webcheck_btn.configure(state="normal")
