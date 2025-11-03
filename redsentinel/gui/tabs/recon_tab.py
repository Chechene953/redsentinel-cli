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
        
        # Troisième ligne - PROFESSIONAL RECON
        buttons_frame3 = ctk.CTkFrame(self.parent)
        buttons_frame3.pack(fill="x", padx=20, pady=(0, 20))
        
        self.full_recon_btn = ctk.CTkButton(
            buttons_frame3,
            text="Full Professional Recon Pipeline",
            command=self.run_full_recon,
            width=600,
            height=45,
            fg_color="#E11D47",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.full_recon_btn.pack(padx=5)
        
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
        """Advanced subdomain enumeration"""
        try:
            from redsentinel.tools.recon_advanced import advanced_subdomain_enum
            
            self.log(f"[*] Starting advanced subdomain enumeration...")
            self.log(f"[*] Using multiple sources: crt.sh, Certspotter, URLScan")
            
            results = await advanced_subdomain_enum(target, use_wordlist=False)
            self.progress_bar.set(1.0)
            
            if results.get("subdomains"):
                self.log(f"[+] Found {results['total_found']} unique subdomains")
                self.log("\n[*] Breakdown by source:")
                for source, count in results.get("sources", {}).items():
                    self.log(f"  • {source}: {count}")
                
                self.log("\n[+] Subdomains:")
                for sub in results["subdomains"][:100]:  # Limit display
                    self.log(f"  • {sub}")
                
                if len(results["subdomains"]) > 100:
                    self.log(f"\n[!] Showing first 100 of {len(results['subdomains'])} results")
            else:
                self.log("[!] No subdomains found")
                
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            self.subdomain_btn.configure(state="normal")
    
    async def _dns_scan(self, target: str):
        """Deep DNS analysis"""
        try:
            from redsentinel.tools.recon_advanced import deep_dns_analysis
            
            self.log(f"[*] Starting comprehensive DNS analysis...")
            
            results = await deep_dns_analysis(target)
            self.progress_bar.set(1.0)
            
            self.log("[+] DNS Analysis complete:\n")
            
            # Display records
            for rtype, data in results.get("records", {}).items():
                if "values" in data:
                    self.log(f"[*] {rtype} Records ({data.get('description', 'N/A')}):")
                    for value in data["values"][:10]:
                        self.log(f"  • {value}")
                    if len(data["values"]) > 10:
                        self.log(f"  ... and {len(data['values']) - 10} more")
                    self.log("")
            
            # Security checks
            if results.get("security_checks"):
                self.log("[*] Security Findings:")
                for check, status in results["security_checks"].items():
                    self.log(f"  • {check}: {status}")
                self.log("")
                
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            self.dns_btn.configure(state="normal")
    
    async def _portscan(self, target: str):
        """Professional port scanning with service detection"""
        try:
            from redsentinel.tools.recon_advanced import comprehensive_port_scan
            
            self.log(f"[*] Starting professional port scan...")
            self.log(f"[*] Target: {target}")
            self.log(f"[*] Scanning top ports with banner grabbing...")
            
            # Top ports for pentesters
            ports = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                    1433, 1723, 3306, 3389, 5432, 5900, 5985, 5986, 8000, 8080, 8443, 9200]
            
            results = await comprehensive_port_scan(target, ports=ports, timeout=3.0, concurrency=100)
            self.progress_bar.set(1.0)
            
            self.log(f"\n[+] Port Scan Summary:")
            self.log(f"  • Scanned: {results['total_scanned']} ports")
            self.log(f"  • Open: {len(results['open_ports'])} ports")
            self.log(f"  • Scan time: {results.get('scan_time', 'N/A')}")
            
            if results.get("open_ports"):
                self.log(f"\n[+] Open Ports & Services:")
                for port in results["open_ports"]:
                    service = results.get("services", {}).get(port, "Unknown")
                    self.log(f"  • Port {port}: {service}")
                    
                    banner = results.get("banners", {}).get(port)
                    if banner:
                        banner_short = banner[:80] + "..." if len(banner) > 80 else banner
                        self.log(f"    Banner: {banner_short}")
            else:
                self.log("\n[!] No open ports found")
                
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
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
    
    def run_full_recon(self):
        """Lance le pipeline de reconnaissance professionnel complet"""
        target = self.get_target()
        if not target:
            return
        self.full_recon_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.log("=" * 80)
        self.log("REDSENTINEL PROFESSIONAL RECONNAISSANCE PIPELINE")
        self.log("=" * 80)
        self.log(f"Target: {target}")
        self.log("=" * 80 + "\n")
        threading.Thread(target=self._async_wrapper, args=(self._full_recon_pipeline, target)).start()
    
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
        """Professional SSL/TLS audit"""
        try:
            from redsentinel.tools.recon_advanced import professional_ssl_audit
            
            self.log(f"[*] Starting professional SSL/TLS audit...")
            
            results = await professional_ssl_audit(target, 443)
            self.progress_bar.set(1.0)
            
            self.log(f"\n[+] SSL/TLS Audit Results:")
            self.log(f"  • Overall Grade: {results.get('grade', 'N/A')}")
            
            if results.get("certificate"):
                cert = results["certificate"]
                self.log(f"\n[*] Certificate Details:")
                subject = cert.get("subject", {})
                if subject:
                    self.log(f"  • Subject: {subject}")
                issuer = cert.get("issuer", {})
                if issuer:
                    self.log(f"  • Issuer: {issuer}")
                if cert.get("notAfter"):
                    self.log(f"  • Expires: {cert.get('notAfter')}")
                
                san = cert.get("subjectAltName", [])
                if san:
                    self.log(f"  • SAN: {len(san)} alternate names")
            
            if results.get("protocols"):
                self.log(f"\n[*] Protocols:")
                for proto, info in results["protocols"].items():
                    self.log(f"  • {proto}: {info}")
            
            if results.get("vulnerabilities"):
                self.log(f"\n[!] Security Issues ({len(results['vulnerabilities'])}):")
                for vuln in results["vulnerabilities"]:
                    self.log(f"  • {vuln}")
            
            if results.get("recommendations"):
                self.log(f"\n[*] Recommendations:")
                for rec in results["recommendations"]:
                    self.log(f"  • {rec}")
                    
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
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
    
    async def _full_recon_pipeline(self, target: str):
        """Pipeline professionnel complet"""
        try:
            from redsentinel.tools.recon_pro import full_recon_pipeline
            
            results = await full_recon_pipeline(target)
            self.progress_bar.set(1.0)
            
            self.log("\n" + "=" * 80)
            self.log("RECONNAISSANCE SUMMARY")
            self.log("=" * 80)
            
            summary = results.get("summary", {})
            for key, value in summary.items():
                self.log(f"  • {key.replace('_', ' ').title()}: {value}")
            
            self.log("\n" + "=" * 80)
            self.log("[+] Full reconnaissance pipeline complete!")
            self.log("=" * 80)
            
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            self.full_recon_btn.configure(state="normal")

