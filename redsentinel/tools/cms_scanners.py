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


async def comprehensive_cms_scan(url):
    """
    Detect CMS and run appropriate scanner
    
    Args:
        url: Site URL
    
    Returns:
        dict with CMS scan results
    """
    results = {
        "url": url,
        "cms_detection": None,
        "scanner_results": None
    }
    
    # First, detect CMS
    detection = cms_detection(url)
    results["cms_detection"] = detection
    
    # Run appropriate scanner
    if detection["cms"] == "WordPress":
        results["scanner_results"] = wpscan_scan(url)
    elif detection["cms"] == "Joomla":
        results["scanner_results"] = joomscan_scan(url)
    elif detection["cms"] == "Drupal":
        results["scanner_results"] = droopescan_scan(url, "drupal")
    else:
        results["scanner_results"] = {"info": "No CMS-specific scanner available"}
    
    return results

