# redsentinel/tools/cms_scanners.py
from redsentinel.tools.external_tool import find_binary, run_command
import logging
import aiohttp

logger = logging.getLogger(__name__)


def cms_detection(url):
    """
    Detect CMS type from a URL
    
    Args:
        url: URL to check
    
    Returns:
        dict with CMS detection results
    """
    result = {
        "url": url,
        "cms": "Unknown",
        "version": None,
        "confidence": 0
    }
    
    try:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def check_cms():
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(url, timeout=10, allow_redirects=True) as resp:
                        headers = resp.headers
                        text = await resp.text()
                        
                        # Check for WordPress
                        if "wp-content" in text or "wp-includes" in text:
                            result["cms"] = "WordPress"
                            result["confidence"] = 90
                            if "wp-content/themes/" in text:
                                # Try to extract version
                                import re
                                version_match = re.search(r'ver=(\d+\.\d+)', text)
                                if version_match:
                                    result["version"] = version_match.group(1)
                        
                        # Check for Drupal
                        elif "Drupal" in text or "drupal.js" in text or "/sites/default" in text:
                            result["cms"] = "Drupal"
                            result["confidence"] = 80
                            import re
                            version_match = re.search(r'Drupal (\d+)', text)
                            if version_match:
                                result["version"] = version_match.group(1)
                        
                        # Check for Joomla
                        elif "joomla" in text.lower() or "/templates/" in text:
                            result["cms"] = "Joomla"
                            result["confidence"] = 75
                            import re
                            version_match = re.search(r'Joomla! (\d+\.\d+)', text)
                            if version_match:
                                result["version"] = version_match.group(1)
                        
                        # Check for PrestaShop
                        elif "prestashop" in text.lower() or "/themes/" in text:
                            result["cms"] = "PrestaShop"
                            result["confidence"] = 70
                        
                        # Check for Magento
                        elif "magento" in text.lower() or "mage/" in text:
                            result["cms"] = "Magento"
                            result["confidence"] = 70
                            
                except Exception as e:
                    logger.error(f"CMS detection error: {e}")
        
        loop.run_until_complete(check_cms())
        loop.close()
        
    except Exception as e:
        logger.error(f"CMS detection failed: {e}")
    
    return result


def wpscan_scan(url, api_token=None):
    """
    Run wpscan (WordPress vulnerability scanner)
    
    Args:
        url: WordPress site URL
        api_token: Optional WPScan API token
    
    Returns:
        dict with scan results
    """
    binpath = find_binary("wpscan")
    if not binpath:
        return {"error": "wpscan not found. Install with: sudo apt install wpscan"}
    
    cmd = f"{binpath} --url {url}"
    if api_token:
        cmd += f" --api-token {api_token}"
    cmd += " -o /tmp/wpscan_output.txt"
    
    rc, out, err = run_command(cmd, timeout=600, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


def joomscan_scan(url):
    """
    Run joomscan (Joomla vulnerability scanner)
    
    Args:
        url: Joomla site URL
    
    Returns:
        dict with scan results
    """
    binpath = find_binary("joomscan")
    if not binpath:
        return {"error": "joomscan not found. Install: https://github.com/OWASP/joomscan"}
    
    cmd = f"{binpath} -u {url} -o /tmp/joomscan_output.txt"
    
    rc, out, err = run_command(cmd, timeout=600, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


def droopescan_scan(url, cms="drupal"):
    """
    Run droopescan (Drupal/Joomla/WordPress/SilverStripe scanner)
    
    Args:
        url: Site URL
        cms: CMS type (drupal, joomla, wordpress, silverstripe)
    
    Returns:
        dict with scan results
    """
    binpath = find_binary("droopescan")
    if not binpath:
        return {"error": "droopescan not found. Install: pip install droopescan"}
    
    cmd = f"{binpath} scan {cms} -u {url} -o /tmp/droopescan_output.txt"
    
    rc, out, err = run_command(cmd, timeout=600, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


async def comprehensive_cms_scan(url, cms_type=None):
    """
    Detect CMS and run appropriate scanner with structured vulnerability output
    
    Args:
        url: Site URL
        cms_type: CMS type to scan (auto-detected if None)
    
    Returns:
        dict with CMS scan results including structured vulnerabilities
    """
    from redsentinel.core.error_handler import get_error_handler, ErrorContext
    from redsentinel.vulns.cve_matcher import search_cve
    
    error_handler = get_error_handler()
    context = ErrorContext("comprehensive_cms_scan", url)
    
    results = {
        "url": url,
        "cms_detection": None,
        "scanner_results": None,
        "vulnerabilities": []
    }
    
    # Detect CMS if not provided
    if cms_type is None:
        detection = cms_detection(url)
        results["cms_detection"] = detection
        cms_type = detection.get("cms", "").lower()
    else:
        results["cms_detection"] = {"cms": cms_type, "confidence": 100}
        cms_type = cms_type.lower()
    
    # Run appropriate scanner
    scanner_output = None
    if cms_type == "wordpress":
        scanner_output = wpscan_scan(url)
    elif cms_type == "joomla":
        scanner_output = joomscan_scan(url)
    elif cms_type == "drupal":
        scanner_output = droopescan_scan(url, "drupal")
    else:
        scanner_output = {"info": "No CMS-specific scanner available"}
    
    results["scanner_results"] = scanner_output
    
    # Parse vulnerabilities from scanner output
    vulnerabilities = []
    
    if scanner_output and not scanner_output.get("error"):
        output_text = scanner_output.get("out", "")
        
        # Extract CVE IDs
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, output_text, re.IGNORECASE)
        
        # Extract vulnerability information
        for cve in set(cves):
            vuln = {
                "id": cve,
                "type": "CMS Vulnerability",
                "severity": "UNKNOWN",
                "description": f"Vulnerability found in {cms_type}",
                "cms": cms_type,
                "url": url,
                "cve_id": cve
            }
            
            # Try to get CVE details
            try:
                cve_info = search_cve(cve)
                if cve_info:
                    vuln["severity"] = cve_info.get("severity", "UNKNOWN")
                    vuln["description"] = cve_info.get("description", vuln["description"])
                    vuln["cvss_score"] = cve_info.get("cvss_score", "")
            except:
                pass
            
            vulnerabilities.append(vuln)
        
        # Extract version-specific vulnerabilities
        version_match = re.search(r'version[:\s]+([\d.]+)', output_text, re.IGNORECASE)
        if version_match:
            version = version_match.group(1)
            results["cms_detection"]["version"] = version
            
            # Check for known vulnerable versions
            vulnerable_versions = {
                "wordpress": {
                    "4.0": ["CVE-2015-2213"],
                    "4.1": ["CVE-2015-2213"],
                    "4.2": ["CVE-2015-2213"]
                },
                "drupal": {
                    "7.0": ["CVE-2014-3704"],  # Drupalgeddon
                    "8.0": ["CVE-2018-7600"]   # Drupalgeddon2
                }
            }
            
            if cms_type in vulnerable_versions:
                for vuln_version, cve_list in vulnerable_versions[cms_type].items():
                    if version.startswith(vuln_version):
                        for cve in cve_list:
                            if cve not in [v["cve_id"] for v in vulnerabilities]:
                                vulnerabilities.append({
                                    "id": cve,
                                    "type": "CMS Version Vulnerability",
                                    "severity": "CRITICAL",
                                    "description": f"Known vulnerable {cms_type} version {version}",
                                    "cms": cms_type,
                                    "version": version,
                                    "url": url,
                                    "cve_id": cve
                                })
    
    results["vulnerabilities"] = vulnerabilities
    results["vulnerability_count"] = len(vulnerabilities)
    
    return results

