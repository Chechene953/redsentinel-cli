#!/usr/bin/env python3
"""
Advanced OSINT Sources Aggregator
Centralized access to all advanced OSINT sources
"""

import logging
from typing import List, Dict, Any, Set
import asyncio

logger = logging.getLogger(__name__)


async def all_advanced_sources(domain: str) -> Dict[str, Any]:
    """
    Collecte des informations depuis toutes les sources OSINT avancées
    
    Args:
        domain: Domaine cible
        
    Returns:
        Dict contenant les résultats de toutes les sources
    """
    results = {
        "domain": domain,
        "subdomains": set(),
        "sources": {},
        "stats": {
            "total_sources": 0,
            "successful_sources": 0,
            "failed_sources": 0
        }
    }
    
    sources = []
    
    # Import des sources disponibles
    try:
        from redsentinel.osint.advanced.ct_logs import ct_logs_search
        sources.append(("Certificate Transparency", ct_logs_search))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.advanced.dns_dumpster import dnsdumpster_search
        sources.append(("DNS Dumpster", dnsdumpster_search))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.advanced.wayback_machine import wayback_subdomains
        sources.append(("Wayback Machine", wayback_subdomains))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.advanced.virustotal_client import VirusTotalClient
        vt = VirusTotalClient()
        sources.append(("VirusTotal", vt.get_subdomains))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.advanced.netcraft import netcraft_search
        sources.append(("Netcraft", netcraft_search))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.cert_sources import search_crt_sh
        sources.append(("crt.sh", search_crt_sh))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.advanced.common_crawl import commoncrawl_search
        sources.append(("Common Crawl", commoncrawl_search))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.shodan_client import ShodanClient
        shodan = ShodanClient()
        sources.append(("Shodan", lambda d: shodan.search_domain(d)))
    except ImportError:
        pass
    
    try:
        from redsentinel.osint.censys_client import CensysClient
        censys = CensysClient()
        sources.append(("Censys", lambda d: censys.search_domain(d)))
    except ImportError:
        pass
    
    results["stats"]["total_sources"] = len(sources)
    
    # Exécuter toutes les sources en parallèle
    tasks = []
    for source_name, source_func in sources:
        tasks.append(_safe_source_call(source_name, source_func, domain))
    
    source_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Agréger les résultats
    for (source_name, _), source_result in zip(sources, source_results):
        if isinstance(source_result, Exception):
            logger.debug(f"Source {source_name} failed: {source_result}")
            results["stats"]["failed_sources"] += 1
            results["sources"][source_name] = {"error": str(source_result)}
        elif source_result:
            results["stats"]["successful_sources"] += 1
            
            # Extraire les sous-domaines
            if isinstance(source_result, dict):
                if "subdomains" in source_result:
                    subs = source_result["subdomains"]
                    if isinstance(subs, (list, set)):
                        results["subdomains"].update(subs)
                elif "domains" in source_result:
                    subs = source_result["domains"]
                    if isinstance(subs, (list, set)):
                        results["subdomains"].update(subs)
                
                results["sources"][source_name] = source_result
            elif isinstance(source_result, (list, set)):
                results["subdomains"].update(source_result)
                results["sources"][source_name] = {"subdomains": list(source_result)}
    
    # Convertir le set en list pour JSON
    results["subdomains"] = sorted(list(results["subdomains"]))
    results["stats"]["total_subdomains"] = len(results["subdomains"])
    
    return results


async def _safe_source_call(source_name: str, func, domain: str):
    """Appel sécurisé d'une source OSINT avec timeout"""
    try:
        # Timeout de 30 secondes par source
        result = await asyncio.wait_for(
            asyncio.to_thread(func, domain) if not asyncio.iscoroutinefunction(func) else func(domain),
            timeout=30.0
        )
        return result
    except asyncio.TimeoutError:
        logger.warning(f"Source {source_name} timed out after 30s")
        return {"error": "timeout"}
    except Exception as e:
        logger.error(f"Source {source_name} error: {e}")
        return {"error": str(e)}


async def subdomain_takeover_check(subdomains: List[str]) -> Dict[str, Any]:
    """
    Vérifie les sous-domaines pour des vulnérabilités de takeover
    
    Args:
        subdomains: Liste de sous-domaines à vérifier
        
    Returns:
        Dict avec les résultats de la vérification
    """
    results = {
        "total_checked": len(subdomains),
        "vulnerable": [],
        "potentially_vulnerable": [],
        "safe": [],
        "errors": []
    }
    
    # Signatures communes de takeover
    takeover_signatures = {
        "github": ["There isn't a GitHub Pages site here", "For root URLs"],
        "heroku": ["No such app", "herokucdn.com"],
        "shopify": ["Sorry, this shop is currently unavailable"],
        "tumblr": ["Whatever you were looking for doesn't currently exist"],
        "wordpress": ["Do you want to register"],
        "amazon_s3": ["NoSuchBucket", "The specified bucket does not exist"],
        "azure": ["404 Web Site not found", "The page you are looking for does not exist"],
        "bitbucket": ["Repository not found"],
        "fastly": ["Fastly error: unknown domain"],
        "ghost": ["The thing you were looking for is no longer here"],
        "helpjuice": ["We could not find what you're looking for"],
        "helpscout": ["No settings were found for this company"],
        "pantheon": ["404 error unknown site"],
        "squarespace": ["No Such Account"],
        "statuspage": ["You are being redirected", "Status page is temporarily unavailable"],
        "surge": ["project not found"],
        "tilda": ["Domain has been assigned", "Please renew your subscription"],
        "unbounce": ["The requested URL was not found on this server"],
        "zendesk": ["Help Center Closed"]
    }
    
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for subdomain in subdomains[:100]:  # Limite à 100 pour éviter trop de requêtes
            tasks.append(_check_subdomain_takeover(session, subdomain, takeover_signatures))
        
        check_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for subdomain, check_result in zip(subdomains[:100], check_results):
            if isinstance(check_result, Exception):
                results["errors"].append({
                    "subdomain": subdomain,
                    "error": str(check_result)
                })
            elif check_result:
                status, provider = check_result
                if status == "vulnerable":
                    results["vulnerable"].append({
                        "subdomain": subdomain,
                        "provider": provider
                    })
                elif status == "potentially_vulnerable":
                    results["potentially_vulnerable"].append({
                        "subdomain": subdomain,
                        "provider": provider
                    })
                else:
                    results["safe"].append(subdomain)
    
    return results


async def _check_subdomain_takeover(session, subdomain: str, signatures: Dict[str, List[str]]):
    """Vérifie un sous-domaine individuel pour takeover"""
    try:
        url = f"http://{subdomain}"
        async with session.get(url, timeout=5, allow_redirects=True) as response:
            text = await response.text()
            
            # Vérifier les signatures
            for provider, signature_list in signatures.items():
                for signature in signature_list:
                    if signature.lower() in text.lower():
                        if response.status == 404:
                            return ("vulnerable", provider)
                        else:
                            return ("potentially_vulnerable", provider)
            
            return ("safe", None)
            
    except Exception as e:
        logger.debug(f"Error checking {subdomain}: {e}")
        return ("error", str(e))


# Alias pour compatibilité
get_all_sources = all_advanced_sources
check_takeover = subdomain_takeover_check


if __name__ == "__main__":
    # Test
    async def test():
        print("Testing advanced sources...")
        results = await all_advanced_sources("example.com")
        print(f"Found {len(results['subdomains'])} subdomains from {results['stats']['successful_sources']} sources")
        
        if results['subdomains']:
            print("\nTesting subdomain takeover check...")
            takeover_results = await subdomain_takeover_check(results['subdomains'][:10])
            print(f"Checked: {takeover_results['total_checked']}")
            print(f"Vulnerable: {len(takeover_results['vulnerable'])}")
    
    asyncio.run(test())

