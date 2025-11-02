# redsentinel/intel/threat_intel.py
import aiohttp
import logging

logger = logging.getLogger(__name__)


async def virustotal_check_ip(ip, api_key):
    """
    Check IP reputation with VirusTotal
    
    Args:
        ip: IP address
        api_key: VirusTotal API key
    
    Returns:
        dict with reputation data
    """
    if not api_key:
        return {"error": "VirusTotal API key required"}
    
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {"apikey": api_key, "ip": ip}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
        return {"error": str(e)}


async def abuseipdb_check(ip, api_key):
    """
    Check IP reputation with AbuseIPDB
    
    Args:
        ip: IP address
        api_key: AbuseIPDB API key
    
    Returns:
        dict with reputation data
    """
    if not api_key:
        return {"error": "AbuseIPDB API key required"}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"AbuseIPDB error: {e}")
        return {"error": str(e)}


async def greynoise_check(ip, api_key=None):
    """
    Check IP with GreyNoise (optional API key)
    
    Args:
        ip: IP address
        api_key: Optional GreyNoise API key
    
    Returns:
        dict with intelligence data
    """
    if api_key:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": api_key}
    else:
        # Use community API (rate-limited)
        url = f"https://api.greynoise.io/v2/noise/context/{ip}"
        headers = {}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return {"status": "unknown", "ip": ip}
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"GreyNoise error: {e}")
        return {"error": str(e)}


async def urlhaus_check_url(url):
    """
    Check URL reputation with URLhaus
    
    Args:
        url: URL to check
    
    Returns:
        dict with threat data
    """
    api_url = f"https://urlhaus-api.abuse.ch/v1/url/"
    data = {"url": url}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, json=data, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"URLhaus error: {e}")
        return {"error": str(e)}


async def urlhaus_check_hash(sha256_hash):
    """
    Check malware hash with URLhaus
    
    Args:
        sha256_hash: SHA256 hash
    
    Returns:
        dict with malware data
    """
    api_url = f"https://urlhaus-api.abuse.ch/v1/payload/"
    data = {"sha256_hash": sha256_hash}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, json=data, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"URLhaus hash check error: {e}")
        return {"error": str(e)}


async def comprehensive_threat_intel(ip, urls=None, hashes=None, api_keys=None):
    """
    Comprehensive threat intelligence gathering
    
    Args:
        ip: IP address to check
        urls: List of URLs to check
        hashes: List of hashes to check
        api_keys: Dict with API keys (virustotal, abuseipdb, greynoise)
    
    Returns:
        dict with all intelligence data
    """
    results = {
        "ip": ip,
        "virustotal": None,
        "abuseipdb": None,
        "greynoise": None,
        "urls": {},
        "hashes": {}
    }
    
    # Check IP reputation
    if ip:
        if api_keys and api_keys.get("virustotal"):
            results["virustotal"] = await virustotal_check_ip(ip, api_keys["virustotal"])
        
        if api_keys and api_keys.get("abuseipdb"):
            results["abuseipdb"] = await abuseipdb_check(ip, api_keys["abuseipdb"])
        
        if api_keys and api_keys.get("greynoise"):
            results["greynoise"] = await greynoise_check(ip, api_keys["greynoise"])
    
    # Check URLs
    if urls:
        for url in urls:
            results["urls"][url] = await urlhaus_check_url(url)
    
    # Check hashes
    if hashes:
        for hash_val in hashes:
            results["hashes"][hash_val] = await urlhaus_check_hash(hash_val)
    
    return results

