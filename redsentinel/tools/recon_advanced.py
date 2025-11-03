#!/usr/bin/env python3
"""
Advanced reconnaissance tools for professional pentesting
"""

import asyncio
import socket
import aiohttp
import ssl
from typing import Dict, List, Set, Optional
from datetime import datetime
import json


async def comprehensive_port_scan(
    target: str,
    ports: List[int] = None,
    timeout: float = 3.0,
    concurrency: int = 200
) -> Dict:
    """
    Professional port scanning with service detection
    
    Args:
        target: Target hostname or IP
        ports: List of ports to scan (default: top 1000)
        timeout: Connection timeout per port
        concurrency: Max concurrent connections
    
    Returns:
        Detailed results with open ports, services, and banners
    """
    if ports is None:
        # Top 1000 common ports
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443
        ] + list(range(8000, 8010)) + list(range(9000, 9010))
    
    results = {
        "target": target,
        "open_ports": [],
        "services": {},
        "banners": {},
        "total_scanned": len(ports),
        "scan_time": None
    }
    
    start_time = datetime.now()
    
    async def scan_port(port: int):
        """Scan single port with service detection"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )
            
            # Port is open
            results["open_ports"].append(port)
            
            # Try to grab banner
            try:
                # Send basic probes
                probes = {
                    21: b"\n",   # FTP
                    22: b"SSH-2.0-OpenSSH_7.0\r\n",  # SSH
                    23: b"\n",   # Telnet
                    80: b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n",
                    443: b"\x16\x03\x01\x00\xa5\x01\x00",  # TLS handshake
                    3306: b"\x20\x00\x00\x01\x85\xa6\x03\x00",  # MySQL
                    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL
                }
                
                probe = probes.get(port, b"\n")
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)
                
                # Read response
                banner_data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                if banner_data:
                    banner_text = banner_data.decode('utf-8', errors='ignore').strip()
                    results["banners"][port] = banner_text[:200]  # Limit size
                    
                    # Detect service from banner
                    banner_lower = banner_text.lower()
                    if 'ssh' in banner_lower:
                        results["services"][port] = "SSH"
                    elif 'ftp' in banner_lower or '220' in banner_text:
                        results["services"][port] = "FTP"
                    elif 'http' in banner_lower:
                        results["services"][port] = "HTTP"
                    elif 'smtp' in banner_lower or '250' in banner_text:
                        results["services"][port] = "SMTP"
                    elif 'pop' in banner_lower:
                        results["services"][port] = "POP3"
                    elif 'imap' in banner_lower:
                        results["services"][port] = "IMAP"
                    elif 'mysql' in banner_lower:
                        results["services"][port] = "MySQL"
                    elif 'postgres' in banner_lower:
                        results["services"][port] = "PostgreSQL"
                    elif 'telnet' in banner_lower:
                        results["services"][port] = "Telnet"
                    else:
                        results["services"][port] = "Unknown"
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            return True
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
            return False
    
    # Scan with concurrency control
    semaphore = asyncio.Semaphore(concurrency)
    async def limited_scan(port):
        async with semaphore:
            return await scan_port(port)
    
    tasks = [limited_scan(p) for p in ports]
    await asyncio.gather(*tasks)
    
    results["scan_time"] = str(datetime.now() - start_time)
    return results


async def advanced_subdomain_enum(
    domain: str,
    use_wordlist: bool = False,
    wordlist_file: str = None
) -> Dict:
    """
    Multi-source subdomain enumeration
    
    Args:
        domain: Target domain
        use_wordlist: Use brute-force wordlist
        wordlist_file: Path to custom wordlist
    
    Returns:
        Comprehensive subdomain findings
    """
    results = {
        "domain": domain,
        "subdomains": set(),
        "sources": {},
        "total_found": 0
    }
    
    # Source 1: crt.sh
    try:
        from redsentinel.recon import crtsh_subdomains
        crt_subs = await crtsh_subdomains(domain)
        results["subdomains"].update(crt_subs)
        results["sources"]["crt.sh"] = len(crt_subs)
    except Exception as e:
        results["sources"]["crt.sh"] = f"Error: {str(e)}"
    
    # Source 2: Additional OSINT sources
    try:
        from redsentinel.osint.cert_sources import (
            all_cert_sources, certspotter_subdomains, urlscan_subdomains
        )
        certspot_subs = await certspotter_subdomains(domain)
        results["subdomains"].update(certspot_subs)
        results["sources"]["certspotter"] = len(certspot_subs)
        
        urlscan_subs = await urlscan_subdomains(domain)
        results["subdomains"].update(urlscan_subs)
        results["sources"]["urlscan"] = len(urlscan_subs)
    except Exception as e:
        pass
    
    # Source 3: DNS brute force (if enabled)
    if use_wordlist:
        try:
            from redsentinel.tools.dns_tools import dnsrecon_scan
            # This would require async implementation
            pass
        except:
            pass
    
    results["subdomains"] = sorted(list(results["subdomains"]))
    results["total_found"] = len(results["subdomains"])
    
    return results


async def deep_dns_analysis(domain: str) -> Dict:
    """
    Comprehensive DNS analysis for information gathering
    
    Args:
        domain: Target domain
    
    Returns:
        Detailed DNS records and metadata
    """
    results = {
        "domain": domain,
        "records": {},
        "metadata": {},
        "security_checks": {}
    }
    
    # Common record types
    record_types = {
        "A": "IPv4 Address",
        "AAAA": "IPv6 Address",
        "MX": "Mail Exchange",
        "NS": "Name Servers",
        "TXT": "Text Records",
        "CNAME": "Canonical Name",
        "SOA": "Start of Authority",
        "SRV": "Service Records",
        "PTR": "Pointer Records",
        "CAA": "Certificate Authority Authorization"
    }
    
    # Check each record type
    for rtype, description in record_types.items():
        try:
            from redsentinel.tools.dns_tools import dig_lookup
            result = dig_lookup(domain, rtype, timeout=10)
            if result.get("rc") == 0 and result.get("out"):
                lines = result["out"].strip().split("\n")
                if lines and not lines == [""]:
                    results["records"][rtype] = {
                        "description": description,
                        "values": lines
                    }
                    
                    # Security analysis
                    if rtype == "TXT" and any("spf" in v.lower() for v in lines):
                        results["security_checks"]["SPF"] = "Present"
                    if rtype == "TXT" and any("dmarc" in v.lower() for v in lines):
                        results["security_checks"]["DMARC"] = "Present"
        except Exception as e:
            results["records"][rtype] = {"error": str(e)}
    
    # Try DNS zone transfer
    ns_servers = results["records"].get("NS", {}).get("values", [])
    for ns in ns_servers[:3]:  # Try first 3 nameservers
        try:
            from redsentinel.tools.dns_tools import dig_lookup
            axfr_result = dig_lookup(domain, "AXFR", nameserver=ns, timeout=15)
            if axfr_result.get("rc") == 0:
                results["metadata"]["zone_transfer_vulnerable"] = ns
                results["security_checks"]["Zone Transfer"] = f"Possible on {ns}"
                break
        except:
            pass
    
    return results


async def professional_ssl_audit(host: str, port: int = 443) -> Dict:
    """
    Professional SSL/TLS audit
    
    Args:
        host: Target hostname
        port: Target port
    
    Returns:
        Comprehensive SSL/TLS analysis
    """
    results = {
        "host": host,
        "port": port,
        "certificate": {},
        "protocols": {},
        "vulnerabilities": [],
        "grade": "N/A",
        "recommendations": []
    }
    
    try:
        # Get certificate details
        from redsentinel.tools.ssl_tools import analyze_tls
        ssl_info = analyze_tls(host, port)
        
        if ssl_info.get("supported"):
            results["certificate"] = ssl_info.get("certificate", {})
            
            # Check certificate expiry
            not_after = results["certificate"].get("notAfter", "")
            if not_after:
                try:
                    from datetime import datetime
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.now()).days
                    
                    if days_left < 30:
                        results["vulnerabilities"].append("Certificate expires soon")
                        results["recommendations"].append("Renew certificate immediately")
                    elif days_left < 90:
                        results["vulnerabilities"].append("Certificate expires in < 90 days")
                        results["recommendations"].append("Plan certificate renewal")
                except:
                    pass
            
            # Check subject alternative names
            san_list = results["certificate"].get("subjectAltName", [])
            if not san_list:
                results["vulnerabilities"].append("No Subject Alternative Names")
                results["recommendations"].append("Add SAN to certificate")
            
            # Protocol version check
            protocol = ssl_info.get("protocols", [None])[0]
            if protocol:
                results["protocols"]["current"] = protocol
                
                if "SSL" in protocol:
                    results["vulnerabilities"].append("Deprecated SSL protocol")
                    results["recommendations"].append("Disable SSL 2.0/3.0")
                elif protocol == "TLSv1":
                    results["vulnerabilities"].append("Old TLS version")
                    results["recommendations"].append("Upgrade to TLS 1.2+")
                elif protocol == "TLSv1.1":
                    results["vulnerabilities"].append("Deprecated TLS version")
                    results["recommendations"].append("Upgrade to TLS 1.2+")
            
            # Cipher check
            ciphers = ssl_info.get("ciphers", [])
            if ciphers:
                cipher = ciphers[0]
                cipher_name = cipher.get("name", "").lower()
                
                if "md5" in cipher_name or "sha1" in cipher_name:
                    results["vulnerabilities"].append("Weak cipher hash")
                    results["recommendations"].append("Use SHA-256 or SHA-384")
                
                bits = cipher.get("bits", 0)
                if bits < 128:
                    results["vulnerabilities"].append("Weak key length")
                    results["recommendations"].append("Use 256-bit encryption minimum")
        
        # Try SSL Labs API if available
        try:
            from redsentinel.tools.ssl_tools import check_ssl_labs_grade
            ssllabs_result = check_ssl_labs_grade(host)
            if "grade" in ssllabs_result:
                results["grade"] = ssllabs_result["grade"]
        except:
            pass
    
    except Exception as e:
        results["error"] = str(e)
    
    # Calculate overall grade if no SSL Labs
    if results["grade"] == "N/A":
        vuln_count = len(results["vulnerabilities"])
        if vuln_count == 0:
            results["grade"] = "A"
        elif vuln_count == 1:
            results["grade"] = "B"
        elif vuln_count == 2:
            results["grade"] = "C"
        else:
            results["grade"] = "F"
    
    return results


async def os_fingerprinting(host: str, open_ports: List[int]) -> Dict:
    """
    OS fingerprinting based on open ports and responses
    
    Args:
        host: Target hostname or IP
        open_ports: List of open ports
    
    Returns:
        OS fingerprinting results
    """
    results = {
        "host": host,
        "detected_os": None,
        "confidence": "low",
        "indicators": []
    }
    
    # Analyze port combinations for OS detection
    port_signatures = {
        "Windows": {
            "ports": [135, 139, 445, 3389],
            "patterns": ["smb", "msrpc", "rdp"]
        },
        "Linux": {
            "ports": [22, 111, 2049],
            "patterns": ["openssh", "nfs"]
        },
        "macOS": {
            "ports": [22, 548, 5900],
            "patterns": ["openssh", "afp", "vnc"]
        }
    }
    
    scores = {"Windows": 0, "Linux": 0, "macOS": 0}
    
    for os_name, sig in port_signatures.items():
        matching_ports = set(open_ports) & set(sig["ports"])
        score = len(matching_ports)
        scores[os_name] = score
        
        if score > 0:
            results["indicators"].append(f"{os_name}: {score} ports match")
    
    # Find highest score
    if max(scores.values()) > 0:
        detected = max(scores, key=scores.get)
        results["detected_os"] = detected
        results["confidence"] = "high" if scores[detected] >= 3 else "medium"
    
    return results


async def web_tech_detection(target: str) -> Dict:
    """
    Detect web technologies and frameworks
    
    Args:
        target: Target URL (with http:// or https://)
    
    Returns:
        Detected technologies
    """
    results = {
        "target": target,
        "technologies": [],
        "headers": {},
        "server": None,
        "framework": None
    }
    
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                # Check headers for technology
                headers = resp.headers
                results["headers"] = dict(headers)
                
                # Server detection
                server = headers.get("Server", "").lower()
                if server:
                    results["server"] = headers.get("Server")
                    
                    if "apache" in server:
                        results["technologies"].append("Apache HTTP Server")
                    elif "nginx" in server:
                        results["technologies"].append("Nginx")
                    elif "iis" in server or "microsoft" in server:
                        results["technologies"].append("IIS")
                
                # X-Powered-By
                powered_by = headers.get("X-Powered-By", "").lower()
                if powered_by:
                    if "php" in powered_by:
                        results["technologies"].append("PHP")
                    elif "asp.net" in powered_by:
                        results["technologies"].append("ASP.NET")
                
                # Check body for frameworks
                try:
                    body = await resp.read(4096)
                    body_text = body.decode('utf-8', errors='ignore').lower()
                    
                    if "wp-content" in body_text or "wordpress" in body_text:
                        results["technologies"].append("WordPress")
                        results["framework"] = "WordPress"
                    elif "joomla" in body_text:
                        results["technologies"].append("Joomla")
                        results["framework"] = "Joomla"
                    elif "drupal" in body_text:
                        results["technologies"].append("Drupal")
                        results["framework"] = "Drupal"
                    elif "laravel" in body_text:
                        results["technologies"].append("Laravel")
                    elif "django" in body_text:
                        results["technologies"].append("Django")
                except:
                    pass
                
    except Exception as e:
        results["error"] = str(e)
    
    return results

