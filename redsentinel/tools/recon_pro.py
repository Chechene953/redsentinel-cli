#!/usr/bin/env python3
"""
PROFESSIONAL RECONNAISSANCE TOOLS
Complete OSINT and passive reconnaissance suite for professional pentesting
"""

import asyncio
import aiohttp
import re
import json
from typing import Dict, List, Set, Optional
from datetime import datetime
from urllib.parse import urlparse, quote
import socket
import dns.resolver
import dns.reversename


class ProfessionalRecon:
    """Professional reconnaissance toolkit"""
    
    def __init__(self):
        self.session = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()


async def passive_recon_complete(domain: str) -> Dict:
    """
    COMPLETE PASSIVE RECONNAISSANCE
    Industry-standard passive information gathering
    
    Args:
        domain: Target domain
    
    Returns:
        Complete passive recon results
    """
    results = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains": set(),
        "ips": set(),
        "emails": set(),
        "technologies": [],
        "dns_records": {},
        "whois": {},
        "cloudflare_check": {},
        "waf_detection": {},
        "http_headers": {},
        "cms_info": {},
        "cloud_buckets": [],
        "github_leaks": [],
        "past_a_records": []
    }
    
    async with ProfessionalRecon() as recon:
        # 1. SUBDOMAIN ENUMERATION - Multiple sources
        print(f"[*] Passive: Subdomain enumeration from 10+ sources...")
        from redsentinel.tools.recon_advanced import advanced_subdomain_enum
        subdomain_results = await advanced_subdomain_enum(domain, use_wordlist=False)
        results["subdomains"].update(subdomain_results.get("subdomains", []))
        
        # Add additional passive sources
        additional_sources = [
            ("alienvault", await _alienvault_subdomains(domain)),
            ("virustotal", await _virustotal_subdomains(domain)),
            ("urlscan", await _urlscan_passive_scan(domain)),
            ("hackertarget", await _hackertarget_subdomains(domain))
        ]
        
        for source_name, source_results in additional_sources:
            if source_results:
                results["subdomains"].update(source_results)
        
        # 2. DNS COMPREHENSIVE
        print(f"[*] Passive: Deep DNS analysis...")
        from redsentinel.tools.recon_advanced import deep_dns_analysis
        dns_results = await deep_dns_analysis(domain)
        results["dns_records"] = dns_results.get("records", {})
        
        # Extract all IPs from DNS
        for rtype, data in results["dns_records"].items():
            if "values" in data:
                for value in data["values"]:
                    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', value)
                    if ip_match:
                        results["ips"].add(ip_match.group())
        
        # 3. WHOIS LOOKUP
        print(f"[*] Passive: Whois lookup...")
        try:
            whois_result = await _whois_lookup_async(domain)
            if whois_result:
                results["whois"] = whois_result
                # Extract emails from whois
                for field, value in whois_result.items():
                    if isinstance(value, str):
                        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                        emails = re.findall(email_pattern, value)
                        results["emails"].update(emails)
        except Exception as e:
            pass
        
        # 4. CLOUDFLARE DETECTION
        print(f"[*] Passive: Cloudflare/CDN detection...")
        from redsentinel.tools.cloud_tools import cloudflare_detection, cloud_provider_detection
        results["cloudflare_check"] = await asyncio.to_thread(cloudflare_detection, domain)
        results["cloud_provider"] = await asyncio.to_thread(cloud_provider_detection, domain)
        
        # 5. WAF DETECTION
        print(f"[*] Passive: WAF detection...")
        results["waf_detection"] = await detect_waf(domain)
        
        # 6. TECHNOLOGY DETECTION
        print(f"[*] Passive: Web technology detection...")
        from redsentinel.tools.recon_advanced import web_tech_detection
        tech_result = await web_tech_detection(f"https://{domain}")
        results["technologies"] = tech_result.get("technologies", [])
        results["http_headers"] = tech_result.get("headers", {})
        
        # 7. CMS DETECTION
        from redsentinel.tools.cms_scanners import cms_detection
        cms_result = await asyncio.to_thread(cms_detection, f"https://{domain}")
        results["cms_info"] = cms_result
        
        # 8. CLOUD S3/GCP/AZURE BUCKETS
        print(f"[*] Passive: Cloud bucket enumeration...")
        results["cloud_buckets"] = await scan_cloud_buckets(domain)
        
        # 9. GITHUB LEAKS
        print(f"[*] Passive: GitHub leak detection...")
        results["github_leaks"] = await check_github_leaks(domain)
        
        # 10. HISTORICAL DATA
        print(f"[*] Passive: Historical DNS records...")
        results["past_a_records"] = await get_historical_dns(domain)
    
    # Convert sets to lists for JSON serialization
    results["subdomains"] = sorted(list(results["subdomains"]))
    results["ips"] = sorted(list(results["ips"]))
    results["emails"] = sorted(list(results["emails"]))
    
    results["summary"] = {
        "subdomains_found": len(results["subdomains"]),
        "ips_found": len(results["ips"]),
        "emails_found": len(results["emails"]),
        "technologies_detected": len(results["technologies"]),
        "waf_detected": results["waf_detection"].get("waf", None),
        "cdn_detected": results["cloudflare_check"].get("behind_cloudflare", False)
    }
    
    return results


async def _alienvault_subdomains(domain: str) -> List[str]:
    """Subdomains from AlienVault OTX"""
    subdomains = []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname")
                        if hostname and domain in hostname:
                            subdomains.append(hostname)
    except:
        pass
    return subdomains


async def _virustotal_subdomains(domain: str, api_key: str = None) -> List[str]:
    """Subdomains from VirusTotal (requires API key)"""
    if not api_key:
        return []
    subdomains = []
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params={"apikey": api_key, "domain": domain}, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains.extend(data.get("subdomains", []))
    except:
        pass
    return subdomains


async def _urlscan_passive_scan(domain: str) -> List[str]:
    """Passive scan from URLScan.io"""
    from redsentinel.osint.cert_sources import urlscan_subdomains
    return await urlscan_subdomains(domain)


async def _hackertarget_subdomains(domain: str) -> List[str]:
    """Subdomains from HackerTarget API"""
    subdomains = []
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.split("\n"):
                        if "," in line:
                            hostname = line.split(",")[0].strip()
                            if hostname:
                                subdomains.append(hostname)
    except:
        pass
    return subdomains


async def _whois_lookup_async(domain: str) -> Optional[Dict]:
    """Async whois lookup"""
    try:
        import pythonwhois
        whois_data = pythonwhois.get_whois(domain)
        
        # Convert to serializable format
        result = {}
        for key, value in whois_data.items():
            if isinstance(value, (str, int, list)):
                result[key] = value
            elif isinstance(value, dict):
                result[key] = dict(value)
        
        return result
    except Exception as e:
        return {"error": str(e)}


async def detect_waf(domain: str) -> Dict:
    """
    Detect Web Application Firewall
    
    Args:
        domain: Target domain
    
    Returns:
        WAF detection results
    """
    result = {
        "domain": domain,
        "waf": None,
        "confidence": "low",
        "indicators": []
    }
    
    try:
        url = f"https://{domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=True, ssl=False, timeout=10) as resp:
                headers = resp.headers
                server = headers.get("Server", "").lower()
                
                # WAF signatures
                waf_signatures = {
                    "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
                    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
                    "incapsula": ["incap_ses", "visid_incap"],
                    "akamai": ["x-akamai-transformed"],
                    "awsec": ["awselb"],
                    "modsecurity": ["mod_security", "modsecurity"],
                    "barracuda": ["barracuda"],
                    "fortinet": ["f5-backserver"],
                    "imperva": ["x-iinfo"]
                }
                
                for waf_name, indicators in waf_signatures.items():
                    for indicator in indicators:
                        if indicator.lower() in server or any(indicator.lower() in h.lower() for h in headers.keys()):
                            result["waf"] = waf_name.upper()
                            result["confidence"] = "high"
                            result["indicators"].append(f"Found {indicator}")
                
                # Check response codes for WAF challenges
                if resp.status in [403, 406, 419, 493, 496, 497, 502, 503, 520, 521, 522, 523]:
                    result["indicators"].append(f"Potential WAF blocking (HTTP {resp.status})")
                    if not result["waf"]:
                        result["confidence"] = "medium"
                
    except Exception as e:
        result["error"] = str(e)
    
    return result


async def scan_cloud_buckets(domain: str) -> List[Dict]:
    """
    Scan for exposed cloud storage buckets
    
    Args:
        domain: Target domain
    
    Returns:
        List of discovered buckets
    """
    buckets = []
    
    # Common bucket name patterns
    patterns = [
        f"{domain}",
        f"www.{domain}",
        f"{domain}-dev",
        f"{domain}-prod",
        f"{domain}-test",
        f"{domain}-backup",
        f"s3-{domain}",
        f"{domain}-assets",
        f"assets.{domain}",
        f"static.{domain}"
    ]
    
    from redsentinel.tools.cloud_tools import check_s3_bucket
    
    for pattern in patterns:
        # Check S3
        s3_result = await check_s3_bucket(pattern)
        if s3_result.get("exists"):
            buckets.append({
                "type": "S3",
                "name": pattern,
                "public": s3_result.get("public", False),
                "listable": s3_result.get("listable", False)
            })
        
        # Check GCP buckets
        gcp_url = f"https://storage.googleapis.com/{pattern}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(gcp_url, timeout=5) as resp:
                    if resp.status == 200:
                        buckets.append({
                            "type": "GCP",
                            "name": pattern,
                            "public": True
                        })
            except:
                pass
    
    return buckets


async def check_github_leaks(domain: str) -> List[Dict]:
    """
    Check for exposed secrets on GitHub
    
    Args:
        domain: Target domain
    
    Returns:
        List of potential leaks
    """
    leaks = []
    
    # Common sensitive file patterns
    sensitive_patterns = [
        f"{domain}",
        f"*.{domain}",
        f"mail.{domain}",
        f"smtp.{domain}"
    ]
    
    # Note: Requires GitHub API token for full functionality
    # This is a basic implementation
    
    for pattern in sensitive_patterns:
        # Check for potential leaks
        # In production, use GitHub API to search code/commits
        leaks.append({
            "pattern": pattern,
            "note": "Manual verification recommended via GitHub search"
        })
    
    return leaks


async def get_historical_dns(domain: str) -> List[str]:
    """
    Get historical DNS records
    
    Args:
        domain: Target domain
    
    Returns:
        List of historical A records
    """
    historical_ips = []
    
    # Use SecurityTrails, Censys, or similar for historical records
    # This is a placeholder
    try:
        # Would call historical DNS API here
        pass
    except:
        pass
    
    return historical_ips


async def dns_bruteforce_async(domain: str, wordlist: List[str] = None) -> List[str]:
    """
    DNS bruteforce enumeration
    
    Args:
        domain: Target domain
        wordlist: Custom wordlist
    
    Returns:
        List of discovered subdomains
    """
    if wordlist is None:
        # Default wordlist
        wordlist = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
            "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
            "exchange", "server", "mx", "chat", "cdn", "api", "svn", "vid",
            "sip", "drm", "gpus", "billing", "wsus", "automated", "sms", "pf",
            "sql", "wap", "sip", "sso", "cdn2", "pmo", "dc", "origin-cdn",
            "stag", "s3", "heroku", "doc", "owncloud", "pandora", "shell",
            "public", "private", "book", "sze", "vpn", "box", "help", "mobile"
        ]
    
    discovered = []
    
    async def check_subdomain(subdomain: str):
        try:
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=2)
            if answers:
                discovered.append(subdomain)
        except:
            pass
    
    # Check subdomains with concurrency
    tasks = [check_subdomain(f"{word}.{domain}") for word in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return discovered


async def comprehensive_dns_reverse(ips: List[str]) -> Dict:
    """
    Reverse DNS lookup for discovered IPs
    
    Args:
        ips: List of IP addresses
    
    Returns:
        Reverse DNS results
    """
    results = {
        "reverse_dns": {},
        "ptr_records": {}
    }
    
    async def reverse_lookup(ip: str):
        try:
            n = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(n, 'PTR', lifetime=3)
            for rdata in answers:
                results["ptr_records"][ip] = str(rdata)
        except:
            pass
    
    tasks = [reverse_lookup(ip) for ip in ips if ip]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return results


async def technology_fingerprinting(url: str) -> Dict:
    """
    Advanced technology fingerprinting
    
    Args:
        url: Target URL
    
    Returns:
        Technology stack information
    """
    from redsentinel.tools.recon_advanced import web_tech_detection
    base_result = await web_tech_detection(url)
    
    technologies = base_result.get("technologies", [])
    headers = base_result.get("headers", {})
    
    # Additional detection
    additional_tech = []
    
    # Check for CDN
    cdn_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS CloudFront": ["x-amz-cf-id"],
        "Fastly": ["fastly-io"],
        "KeyCDN": ["server: keycdn-engine"],
        "StackPath": ["server: spserver"]
    }
    
    for cdn, indicators in cdn_signatures.items():
        for indicator in indicators:
            if any(indicator.lower() in str(v).lower() for v in headers.values()):
                additional_tech.append(f"CDN: {cdn}")
                break
    
    return {
        **base_result,
        "technologies": technologies + additional_tech
    }


async def email_harvesting_passive(domain: str) -> List[str]:
    """
    Passive email harvesting
    
    Args:
        domain: Target domain
    
    Returns:
        List of email addresses
    """
    emails = set()
    
    # Method 1: Whois
    try:
        whois_result = await _whois_lookup_async(domain)
        if whois_result:
            import re
            for field, value in whois_result.items():
                if isinstance(value, str):
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    found = re.findall(email_pattern, value)
                    emails.update(found)
    except:
        pass
    
    # Method 2: GitHub search
    try:
        # Search GitHub for emails related to domain
        async with aiohttp.ClientSession() as session:
            search_query = f"email {domain}"
            url = f"https://api.github.com/search/code"
            # Would need API key for full functionality
    except:
        pass
    
    # Method 3: DNS TXT records (SPF)
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata)
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            found = re.findall(email_pattern, txt_record)
            emails.update(found)
    except:
        pass
    
    return sorted(list(emails))


async def sitemap_discovery(url: str) -> Dict:
    """
    Discover sitemaps and robots.txt
    
    Args:
        url: Target URL
    
    Returns:
        Sitemap and robots.txt findings
    """
    result = {
        "robots_txt": None,
        "sitemaps": [],
        "user_agents": [],
        "disallowed": []
    }
    
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    # Check robots.txt
    robots_url = f"{url}/robots.txt"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(robots_url, timeout=10) as resp:
                if resp.status == 200:
                    robots_content = await resp.text()
                    result["robots_txt"] = robots_content
                    
                    # Parse robots.txt
                    for line in robots_content.split("\n"):
                        if line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            result["sitemaps"].append(sitemap_url)
                        elif line.lower().startswith("user-agent:"):
                            ua = line.split(":", 1)[1].strip()
                            result["user_agents"].append(ua)
                        elif line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            result["disallowed"].append(path)
    except:
        pass
    
    # Common sitemap locations
    common_sitemaps = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml"]
    for sitemap_path in common_sitemaps:
        try:
            async with aiohttp.ClientSession() as session:
                sitemap_url = f"{url}{sitemap_path}"
                async with session.get(sitemap_url, timeout=5) as resp:
                    if resp.status == 200:
                        result["sitemaps"].append(sitemap_url)
        except:
            pass
    
    return result


async def api_discovery_passive(url: str) -> List[str]:
    """
    Passive API endpoint discovery
    
    Args:
        url: Target URL
    
    Returns:
        List of discovered API endpoints
    """
    endpoints = []
    
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    # Common API paths
    api_paths = [
        "/api/v1", "/api/v2", "/api/v3",
        "/rest/api", "/graphql", "/graphiql",
        "/api/documentation", "/swagger", "/swagger.json",
        "/api-docs", "/openapi.json", "/openapi.yaml"
    ]
    
    async with aiohttp.ClientSession() as session:
        for path in api_paths:
            try:
                api_url = f"{url}{path}"
                async with session.get(api_url, timeout=5) as resp:
                    if resp.status != 404:
                        endpoints.append({
                            "url": api_url,
                            "status": resp.status,
                            "type": "potential_api"
                        })
            except:
                pass
    
    return endpoints


async def full_recon_pipeline(domain: str) -> Dict:
    """
    COMPLETE PROFESSIONAL RECON PIPELINE
    Full reconnaissance workflow for professional pentesting
    
    Args:
        domain: Target domain
    
    Returns:
        Complete recon report
    """
    print(f"\n{'='*80}")
    print(f" REDSENTINEL PROFESSIONAL RECONNAISSANCE PIPELINE")
    print(f"{'='*80}")
    print(f"Target: {domain}")
    print(f"{'='*80}\n")
    
    full_report = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "passive_recon": {},
        "active_recon": {},
        "summary": {}
    }
    
    # PHASE 1: PASSIVE RECONNAISSANCE
    print("[*] PHASE 1: PASSIVE RECONNAISSANCE")
    print("-" * 80)
    full_report["passive_recon"] = await passive_recon_complete(domain)
    
    # PHASE 2: ACTIVE RECONNAISSANCE
    print("\n[*] PHASE 2: ACTIVE RECONNAISSANCE")
    print("-" * 80)
    
    # Subdomains found
    subdomains = full_report["passive_recon"].get("subdomains", [])
    
    # DNS bruteforce
    print("[*] Active: DNS bruteforce enumeration...")
    brute_subs = await dns_bruteforce_async(domain)
    subdomains.extend(brute_subs)
    subdomains = list(set(subdomains))
    
    # Reverse DNS
    ips = full_report["passive_recon"].get("ips", [])
    if ips:
        print("[*] Active: Reverse DNS lookup...")
        reverse_results = await comprehensive_dns_reverse(ips)
        full_report["active_recon"]["reverse_dns"] = reverse_results
    
    # Sitemap discovery
    print("[*] Active: Sitemap and robots.txt discovery...")
    sitemap_results = await sitemap_discovery(f"https://{domain}")
    full_report["active_recon"]["sitemap"] = sitemap_results
    
    # API discovery
    print("[*] Active: API endpoint discovery...")
    api_results = await api_discovery_passive(f"https://{domain}")
    full_report["active_recon"]["api_endpoints"] = api_results
    
    # Technology fingerprinting
    print("[*] Active: Technology fingerprinting...")
    tech_results = await technology_fingerprinting(f"https://{domain}")
    full_report["active_recon"]["technologies"] = tech_results
    
    # Email harvesting
    print("[*] Active: Email harvesting...")
    emails = await email_harvesting_passive(domain)
    full_report["active_recon"]["emails"] = emails
    
    full_report["active_recon"]["subdomains"] = subdomains
    
    # FINAL SUMMARY
    print("\n" + "=" * 80)
    print(" RECONNAISSANCE SUMMARY")
    print("=" * 80)
    
    summary = {
        "total_subdomains": len(subdomains),
        "total_ips": len(full_report["passive_recon"].get("ips", [])),
        "total_emails": len(emails),
        "technologies": len(full_report["active_recon"]["technologies"].get("technologies", [])),
        "waf_detected": full_report["passive_recon"].get("waf_detection", {}).get("waf"),
        "cdn_detected": full_report["passive_recon"].get("cloudflare_check", {}).get("behind_cloudflare"),
        "cloud_buckets": len(full_report["passive_recon"].get("cloud_buckets", [])),
        "api_endpoints": len(api_results),
        "robots_txt": sitemap_results.get("robots_txt") is not None,
        "sitemaps_found": len(sitemap_results.get("sitemaps", []))
    }
    
    full_report["summary"] = summary
    
    # Print summary
    for key, value in summary.items():
        print(f"  • {key.replace('_', ' ').title()}: {value}")
    
    print("=" * 80)
    
    return full_report

