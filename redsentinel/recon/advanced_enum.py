#!/usr/bin/env python3
"""
Advanced Enumeration Module
Comprehensive reconnaissance pipeline with multiple sources
"""

import asyncio
import logging
from typing import Dict, List, Any, Set
import dns.resolver
import socket

logger = logging.getLogger(__name__)


async def comprehensive_recon_pipeline(domain: str, **kwargs) -> Dict[str, Any]:
    """
    Pipeline de reconnaissance complet utilisant toutes les sources disponibles
    
    Args:
        domain: Domaine cible
        **kwargs: Options additionnelles
        
    Returns:
        Dict contenant tous les résultats de reconnaissance
    """
    results = {
        "domain": domain,
        "passive": {},
        "active": {},
        "subdomains": [],
        "ips": [],
        "ports": {},
        "services": {},
        "technologies": []
    }
    
    logger.info(f"Starting comprehensive recon for {domain}")
    
    # Phase 1: Passive Enumeration
    logger.info("Phase 1: Passive enumeration")
    passive_results = await passive_subdomain_enum(domain)
    results["passive"] = passive_results
    results["subdomains"].extend(passive_results.get("subdomains", []))
    
    # Phase 2: Active Enumeration (si activé)
    if kwargs.get("active", True):
        logger.info("Phase 2: Active enumeration")
        active_results = await active_subdomain_enum(domain, passive_results.get("subdomains", []))
        results["active"] = active_results
        results["subdomains"].extend(active_results.get("subdomains", []))
    
    # Dédupliquer les sous-domaines
    results["subdomains"] = sorted(list(set(results["subdomains"])))
    
    # Phase 3: Resolution DNS
    if kwargs.get("resolve_dns", True):
        logger.info("Phase 3: DNS resolution")
        results["dns_resolution"] = await resolve_subdomains(results["subdomains"])
        results["ips"] = list(set(results["dns_resolution"].get("ips", [])))
    
    # Phase 4: Port Scanning (si activé)
    if kwargs.get("port_scan", False):
        logger.info("Phase 4: Port scanning")
        results["ports"] = await scan_ports(results["ips"])
    
    # Statistiques
    results["stats"] = {
        "total_subdomains": len(results["subdomains"]),
        "total_ips": len(results["ips"]),
        "passive_sources": len(results["passive"].get("sources", {})),
        "active_sources": len(results["active"].get("sources", {}))
    }
    
    logger.info(f"Recon complete: {results['stats']['total_subdomains']} subdomains found")
    
    return results


async def passive_subdomain_enum(domain: str) -> Dict[str, Any]:
    """
    Énumération passive de sous-domaines depuis multiples sources
    
    Args:
        domain: Domaine cible
        
    Returns:
        Dict avec les sous-domaines trouvés et les sources utilisées
    """
    results = {
        "domain": domain,
        "subdomains": set(),
        "sources": {},
        "stats": {
            "total_sources": 0,
            "successful_sources": 0
        }
    }
    
    # Import des sources OSINT
    try:
        from redsentinel.osint.advanced_sources import all_advanced_sources
        osint_results = await all_advanced_sources(domain)
        
        if osint_results and "subdomains" in osint_results:
            results["subdomains"].update(osint_results["subdomains"])
            results["sources"]["osint"] = osint_results
            results["stats"]["total_sources"] += osint_results.get("stats", {}).get("total_sources", 0)
            results["stats"]["successful_sources"] += osint_results.get("stats", {}).get("successful_sources", 0)
    except Exception as e:
        logger.error(f"OSINT sources error: {e}")
    
    # Certificate Transparency Logs
    try:
        from redsentinel.osint.cert_sources import search_crt_sh
        ct_results = await asyncio.to_thread(search_crt_sh, domain)
        if ct_results:
            results["subdomains"].update(ct_results)
            results["sources"]["crtsh"] = list(ct_results)
            results["stats"]["total_sources"] += 1
            results["stats"]["successful_sources"] += 1
    except Exception as e:
        logger.error(f"crt.sh error: {e}")
    
    # DNS Enumeration
    try:
        dns_results = await dns_enumeration(domain)
        if dns_results:
            results["subdomains"].update(dns_results)
            results["sources"]["dns"] = dns_results
            results["stats"]["total_sources"] += 1
            results["stats"]["successful_sources"] += 1
    except Exception as e:
        logger.error(f"DNS enumeration error: {e}")
    
    # Convertir set en list
    results["subdomains"] = sorted(list(results["subdomains"]))
    results["stats"]["total_subdomains"] = len(results["subdomains"])
    
    return results


async def active_subdomain_enum(domain: str, known_subdomains: List[str] = None) -> Dict[str, Any]:
    """
    Énumération active de sous-domaines (bruteforce, permutations, etc.)
    
    Args:
        domain: Domaine cible
        known_subdomains: Liste de sous-domaines déjà connus
        
    Returns:
        Dict avec les nouveaux sous-domaines trouvés
    """
    results = {
        "domain": domain,
        "subdomains": set(),
        "sources": {},
        "stats": {
            "total_sources": 0,
            "successful_sources": 0
        }
    }
    
    # Permutations de sous-domaines connus
    if known_subdomains:
        try:
            permutations = await generate_permutations(domain, known_subdomains)
            validated = await validate_subdomains(permutations)
            results["subdomains"].update(validated)
            results["sources"]["permutations"] = list(validated)
            results["stats"]["total_sources"] += 1
            if validated:
                results["stats"]["successful_sources"] += 1
        except Exception as e:
            logger.error(f"Permutation error: {e}")
    
    # Bruteforce commun
    try:
        common_subs = await bruteforce_common_subdomains(domain)
        results["subdomains"].update(common_subs)
        results["sources"]["bruteforce"] = list(common_subs)
        results["stats"]["total_sources"] += 1
        if common_subs:
            results["stats"]["successful_sources"] += 1
    except Exception as e:
        logger.error(f"Bruteforce error: {e}")
    
    # Convertir set en list
    results["subdomains"] = sorted(list(results["subdomains"]))
    results["stats"]["total_subdomains"] = len(results["subdomains"])
    
    return results


async def dns_enumeration(domain: str) -> Set[str]:
    """Énumération DNS basique"""
    subdomains = set()
    
    common_records = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
                     'admin', 'api', 'dev', 'stage', 'test', 'vpn', 'remote']
    
    async def check_subdomain(sub):
        try:
            full_domain = f"{sub}.{domain}" if sub else domain
            await asyncio.to_thread(socket.gethostbyname, full_domain)
            return full_domain
        except:
            return None
    
    tasks = [check_subdomain(sub) for sub in common_records]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if result and not isinstance(result, Exception):
            subdomains.add(result)
    
    return subdomains


async def generate_permutations(domain: str, subdomains: List[str]) -> Set[str]:
    """Génère des permutations de sous-domaines"""
    permutations = set()
    
    # Préfixes et suffixes communs
    prefixes = ['dev', 'stage', 'test', 'prod', 'beta', 'alpha', 'demo', 'uat']
    suffixes = ['api', 'admin', 'portal', 'app', 'web', 'mobile']
    
    for sub in subdomains[:10]:  # Limiter pour éviter trop de combinaisons
        base = sub.replace(f'.{domain}', '')
        
        # Ajouter préfixes
        for prefix in prefixes:
            permutations.add(f"{prefix}-{base}.{domain}")
            permutations.add(f"{prefix}{base}.{domain}")
        
        # Ajouter suffixes
        for suffix in suffixes:
            permutations.add(f"{base}-{suffix}.{domain}")
            permutations.add(f"{base}{suffix}.{domain}")
    
    return permutations


async def validate_subdomains(subdomains: Set[str]) -> Set[str]:
    """Valide l'existence des sous-domaines"""
    valid = set()
    
    async def check(subdomain):
        try:
            await asyncio.to_thread(socket.gethostbyname, subdomain)
            return subdomain
        except:
            return None
    
    tasks = [check(sub) for sub in list(subdomains)[:100]]  # Limiter à 100
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if result and not isinstance(result, Exception):
            valid.add(result)
    
    return valid


async def bruteforce_common_subdomains(domain: str) -> Set[str]:
    """Bruteforce de sous-domaines communs"""
    common = [
        'www', 'mail', 'webmail', 'ftp', 'admin', 'administrator', 'api', 'app',
        'blog', 'cdn', 'cloud', 'dev', 'development', 'docs', 'forum', 'help',
        'mobile', 'news', 'portal', 'secure', 'shop', 'stage', 'staging', 'support',
        'test', 'testing', 'vpn', 'beta', 'alpha', 'demo', 'old', 'new', 'v2',
        'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns', 'mx', 'ssh', 'sftp', 'remote'
    ]
    
    found = set()
    
    async def check(sub):
        try:
            full = f"{sub}.{domain}"
            await asyncio.to_thread(socket.gethostbyname, full)
            return full
        except:
            return None
    
    tasks = [check(sub) for sub in common]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if result and not isinstance(result, Exception):
            found.add(result)
    
    return found


async def resolve_subdomains(subdomains: List[str]) -> Dict[str, Any]:
    """Résout les sous-domaines en adresses IP"""
    results = {
        "resolved": {},
        "failed": [],
        "ips": set()
    }
    
    async def resolve(subdomain):
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, subdomain)
            return (subdomain, ip)
        except:
            return (subdomain, None)
    
    tasks = [resolve(sub) for sub in subdomains[:200]]  # Limiter à 200
    resolution_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in resolution_results:
        if result and not isinstance(result, Exception):
            subdomain, ip = result
            if ip:
                results["resolved"][subdomain] = ip
                results["ips"].add(ip)
            else:
                results["failed"].append(subdomain)
    
    results["ips"] = list(results["ips"])
    results["stats"] = {
        "total": len(subdomains),
        "resolved": len(results["resolved"]),
        "failed": len(results["failed"])
    }
    
    return results


async def scan_ports(ips: List[str]) -> Dict[str, Any]:
    """Scan de ports basique"""
    results = {}
    
    common_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]
    
    async def check_port(ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None
    
    for ip in ips[:10]:  # Limiter à 10 IPs
        tasks = [check_port(ip, port) for port in common_ports]
        port_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = [p for p in port_results if p and not isinstance(p, Exception)]
        if open_ports:
            results[ip] = open_ports
    
    return results


if __name__ == "__main__":
    # Test
    async def test():
        print("Testing comprehensive recon pipeline...")
        results = await comprehensive_recon_pipeline("example.com", active=False, port_scan=False)
        print(f"Found {len(results['subdomains'])} subdomains")
        print(f"Passive sources: {results['stats']['passive_sources']}")
    
    asyncio.run(test())

