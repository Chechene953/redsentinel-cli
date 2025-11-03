#!/usr/bin/env python3
"""
Tab de Reconnaissance & Énumération
"""

import customtkinter as ctk
import asyncio
import threading
from typing import Optional


class ReconTab:
    """Onglet de reconnaissance"""
    
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface utilisateur"""
        # Section input target
        input_frame = ctk.CTkFrame(self.parent)
        input_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            input_frame,
            text="Cible:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left", padx=10, pady=10)
        
        self.target_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="example.com",
            width=400,
            font=ctk.CTkFont(size=12)
        )
        self.target_entry.pack(side="left", padx=10, pady=10)
        
        # Boutons d'action
        buttons_frame = ctk.CTkFrame(self.parent)
        buttons_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.subdomain_btn = ctk.CTkButton(
            buttons_frame,
            text="Subdomain Discovery (crt.sh)",
            command=self.run_subdomain_scan,
            width=200,
            height=40
        )
        self.subdomain_btn.pack(side="left", padx=5)
        
        self.dns_btn = ctk.CTkButton(
            buttons_frame,
            text="DNS Enumeration",
            command=self.run_dns_scan,
            width=200,
            height=40
        )
        self.dns_btn.pack(side="left", padx=5)
        
        self.portscan_btn = ctk.CTkButton(
            buttons_frame,
            text="Quick Port Scan",
            command=self.run_portscan,
            width=200,
            height=40
        )
        self.portscan_btn.pack(side="left", padx=5)
        
        # Deuxième ligne de boutons
        buttons_frame2 = ctk.CTkFrame(self.parent)
        buttons_frame2.pack(fill="x", padx=20, pady=(0, 20))
        
        self.nmap_btn = ctk.CTkButton(
            buttons_frame2,
            text="Nmap Scan",
            command=self.run_nmap,
            width=200,
            height=40
        )
        self.nmap_btn.pack(side="left", padx=5)
        
        self.masscan_btn = ctk.CTkButton(
            buttons_frame2,
            text="Masscan",
            command=self.run_masscan,
            width=200,
            height=40
        )
        self.masscan_btn.pack(side="left", padx=5)
        
        self.ssl_btn = ctk.CTkButton(
            buttons_frame2,
            text="SSL/TLS Analysis",
            command=self.run_ssl,
            width=200,
            height=40
        )
        self.ssl_btn.pack(side="left", padx=5)
        
        self.cloud_btn = ctk.CTkButton(
            buttons_frame2,
            text="Cloud Discovery",
            command=self.run_cloud,
            width=200,
            height=40
        )
        self.cloud_btn.pack(side="left", padx=5)
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.parent)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 10))
        
        # Zone de résultats
        results_frame = ctk.CTkFrame(self.parent)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        ctk.CTkLabel(
            results_frame,
            text="Résultats:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        self.results_text = ctk.CTkTextbox(
            results_frame,
            font=ctk.CTkFont(size=11, family="Courier")
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Boutons d'export
        export_frame = ctk.CTkFrame(self.parent)
        export_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkButton(
            export_frame,
            text="Export CSV",
            command=self.export_csv,
            width=120
        ).pack(side="right", padx=5)
        
        ctk.CTkButton(
            export_frame,
            text="Export TXT",
            command=self.export_txt,
            width=120
        ).pack(side="right", padx=5)
        
        ctk.CTkButton(
            export_frame,
            text="Clear",
            command=self.clear_results,
            width=120
        ).pack(side="right", padx=5)
    
    def get_target(self) -> Optional[str]:
        """Récupère la cible depuis l'input"""
        target = self.target_entry.get().strip()
        if not target:
            self.log("ERROR: Veuillez entrer une cible!")
            return None
        return target
    
    def log(self, message: str):
        """Affiche un message dans les résultats"""
        self.results_text.insert("end", message + "\n")
        self.results_text.see("end")
    
    def run_subdomain_scan(self):
        """Lance un scan de sous-domaines"""
        target = self.get_target()
        if not target:
            return
        
        self.subdomain_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting subdomain scan for {target}...")
        
        # Lancer dans un thread pour ne pas bloquer la GUI
        thread = threading.Thread(
            target=self._async_wrapper,
            args=(self._subdomain_scan, target)
        )
        thread.start()
    
    def run_dns_scan(self):
        """Lance un scan DNS"""
        target = self.get_target()
        if not target:
            return
        
        self.dns_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting DNS enumeration for {target}...")
        
        thread = threading.Thread(
            target=self._async_wrapper,
            args=(self._dns_scan, target)
        )
        thread.start()
    
    def run_portscan(self):
        """Lance un scan de ports"""
        target = self.get_target()
        if not target:
            return
        
        self.portscan_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting port scan for {target}...")
        
        thread = threading.Thread(
            target=self._async_wrapper,
            args=(self._portscan, target)
        )
        thread.start()
    
    def _async_wrapper(self, coro_func, *args):
        """Wrapper pour exécuter des fonctions async dans un thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(coro_func(*args))
        finally:
            loop.close()
    
    async def _subdomain_scan(self, target: str):
        """Scan asynchrone de sous-domaines"""
        try:
            from redsentinel.recon import crtsh_subdomains
            
            subs = await crtsh_subdomains(target)
            self.progress_bar.set(1.0)
            
            if subs:
                self.log(f"[+] Found {len(subs)} subdomains:")
                for sub in subs:
                    self.log(f"  • {sub}")
            else:
                self.log("[!] No subdomains found")
                
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.subdomain_btn.configure(state="normal")
    
    async def _dns_scan(self, target: str):
        """Scan asynchrone DNS"""
        try:
            from redsentinel.tools.dns_tools import comprehensive_dns_enum
            
            results = await comprehensive_dns_enum(target)
            self.progress_bar.set(1.0)
            
            self.log("[+] DNS Enumeration complete:")
            self.log(str(results))
                
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.dns_btn.configure(state="normal")
    
    async def _portscan(self, target: str):
        """Scan asynchrone de ports"""
        try:
            from redsentinel.scanner import scan_ports
            
            ports = [80, 443, 22, 21, 8080, 3306, 5432]
            results = await scan_ports([target], ports)
            self.progress_bar.set(1.0)
            
            self.log("[+] Port scan complete:")
            if isinstance(results, list):
                for result in results:
                    self.log(f"  • {result}")
            else:
                self.log(str(results))
                
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.portscan_btn.configure(state="normal")
    
    def run_nmap(self):
        """Lance un scan Nmap"""
        target = self.get_target()
        if not target:
            return
        self.nmap_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Nmap scan for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._nmap_scan, target)).start()
    
    def run_masscan(self):
        """Lance un scan Masscan"""
        target = self.get_target()
        if not target:
            return
        self.masscan_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Masscan for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._masscan, target)).start()
    
    def run_ssl(self):
        """Lance une analyse SSL/TLS"""
        target = self.get_target()
        if not target:
            return
        self.ssl_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting SSL/TLS analysis for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._ssl_scan, target)).start()
    
    def run_cloud(self):
        """Lance un scan cloud"""
        target = self.get_target()
        if not target:
            return
        self.cloud_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"[*] Starting Cloud discovery for {target}...")
        threading.Thread(target=self._async_wrapper, args=(self._cloud_scan, target)).start()
    
    async def _nmap_scan(self, target: str):
        """Scan Nmap asynchrone"""
        try:
            from redsentinel.tools.nmap_wrapper import nmap_scan_nm
            results = await nmap_scan_nm([target])
            self.progress_bar.set(1.0)
            self.log("[+] Nmap scan complete:")
            self.log(str(results) if results else "Aucun résultat")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.nmap_btn.configure(state="normal")
    
    async def _masscan(self, target: str):
        """Scan Masscan asynchrone"""
        try:
            from redsentinel.tools.masscan_wrapper import masscan_scan
            results = await masscan_scan(target, ports="1-65535")
            self.progress_bar.set(1.0)
            self.log("[+] Masscan complete:")
            self.log(str(results) if results else "Aucun résultat")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.masscan_btn.configure(state="normal")
    
    async def _ssl_scan(self, target: str):
        """Analyse SSL/TLS asynchrone"""
        try:
            from redsentinel.tools.ssl_tools import comprehensive_ssl_analysis
            results = await comprehensive_ssl_analysis(target, 443)
            self.progress_bar.set(1.0)
            self.log("[+] SSL/TLS analysis complete:")
            self.log(str(results) if results else "Aucun résultat")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.ssl_btn.configure(state="normal")
    
    async def _cloud_scan(self, target: str):
        """Scan cloud asynchrone"""
        try:
            from redsentinel.tools.cloud_tools import cloud_provider_detection, check_s3_bucket, cloudflare_detection
            self.log("[*] Detecting cloud provider...")
            provider = await cloud_provider_detection(target)
            self.log(f"  Provider: {provider}")
            
            self.log("[*] Testing S3 buckets...")
            s3_result = await check_s3_bucket(target)
            self.log(f"  S3: {s3_result}")
            
            self.log("[*] Detecting Cloudflare...")
            cf_result = await cloudflare_detection(target)
            self.log(f"  Cloudflare: {cf_result}")
            
            self.progress_bar.set(1.0)
            self.log("[+] Cloud discovery complete")
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
        finally:
            self.cloud_btn.configure(state="normal")
    
    def export_csv(self):
        """Exporte les résultats en CSV"""
        self.log("[*] CSV export - development")
    
    def export_txt(self):
        """Exporte les résultats en TXT"""
        self.log("[*] TXT export - development")
    
    def clear_results(self):
        """Efface les résultats"""
        self.results_text.delete("1.0", "end")

