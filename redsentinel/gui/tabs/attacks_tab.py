#!/usr/bin/env python3
"""
Tab Exploitation & Attacks
"""

import customtkinter as ctk
import asyncio
import threading


class AttacksTab:
    """Onglet d'exploitation"""
    
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface"""
        # Warning
        warning_frame = ctk.CTkFrame(self.parent)
        warning_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            warning_frame,
            text="WARNING: AUTHORIZED USE ONLY - ILLEGAL WITHOUT PERMISSION !",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="red"
        ).pack(padx=20, pady=10)
        
        # Input
        input_frame = ctk.CTkFrame(self.parent)
        input_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(input_frame, text="Cible:", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
        self.target_entry = ctk.CTkEntry(input_frame, placeholder_text="example.com", width=400)
        self.target_entry.pack(side="left", padx=10)
        
        # Boutons
        buttons_frame = ctk.CTkFrame(self.parent)
        buttons_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.ffuf_btn = ctk.CTkButton(buttons_frame, text="Directory Brute Force (ffuf)", command=self.run_ffuf, width=200, height=40)
        self.ffuf_btn.pack(side="left", padx=5)
        
        self.password_btn = ctk.CTkButton(buttons_frame, text="Password Attack", command=self.run_password, width=200, height=40)
        self.password_btn.pack(side="left", padx=5)
        
        self.exploit_btn = ctk.CTkButton(buttons_frame, text="Exploit Search", command=self.run_exploit, width=200, height=40)
        self.exploit_btn.pack(side="left", padx=5)
        
        self.api_btn = ctk.CTkButton(buttons_frame, text="API Security Testing", command=self.run_api, width=200, height=40)
        self.api_btn.pack(side="left", padx=5)
        
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
    
    def run_ffuf(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.ffuf_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Directory Brute Force for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._ffuf_scan, target)).start()
    
    def run_password(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.password_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Password Attack for {target}...")
        self.log("[*] In development")
        self.progress_bar.set(1.0)
        self.password_btn.configure(state="normal")
    
    def run_exploit(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.exploit_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Exploit Search for {target}...")
        self.log("[*] In development")
        self.progress_bar.set(1.0)
        self.exploit_btn.configure(state="normal")
    
    def run_api(self):
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Please enter a target!")
            return
        self.api_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting API Security Testing for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._api_scan, target)).start()
    
    async def _ffuf_scan(self, target: str):
        try:
            url = f"https://{target}" if not target.startswith(("http://", "https://")) else target
            from redsentinel.tools.ffuf_wrapper import ffuf_scan
            results = await ffuf_scan(url)
            self.progress_bar.set(1.0)
            self.log("[+] Directory Brute Force complete")
            self.log(str(results) if results else "No results")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.ffuf_btn.configure(state="normal")
    
    async def _api_scan(self, target: str):
        try:
            url = f"https://{target}/api" if not target.startswith(("http://", "https://")) else f"{target}/api"
            from redsentinel.api.security_testing import comprehensive_api_security_scan
            results = await comprehensive_api_security_scan(url)
            self.progress_bar.set(1.0)
            self.log("[+] API Security Testing complete")
            self.log(str(results) if results else "No results")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.api_btn.configure(state="normal")
