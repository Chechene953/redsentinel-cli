# redsentinel/osint/shodan_client.py
import aiohttp
import logging

logger = logging.getLogger(__name__)


async def shodan_search_host(ip, api_key):
    """
    Search for IP information on Shodan
    
    Args:
        ip: IP address
        api_key: Shodan API key
    
    Returns:
        dict with host information
    """
    if not api_key:
        return {"error": "Shodan API key required"}
    
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": api_key}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"Shodan error: {e}")
        return {"error": str(e)}


async def shodan_search(query, api_key, facets=None):
    """
    Search Shodan database
    
    Args:
        query: Search query
        api_key: Shodan API key
        facets: Optional facets for result grouping
    
    Returns:
        dict with search results
    """
    if not api_key:
        return {"error": "Shodan API key required"}
    
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": api_key, "query": query}
    
    if facets:
        params["facets"] = facets
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"Shodan search error: {e}")
        return {"error": str(e)}


async def shodan_certificate_search(domain, api_key):
    """
    Search for SSL certificates on Shodan
    
    Args:
        domain: Domain to search
        api_key: Shodan API key
    
    Returns:
        dict with certificate results
    """
    if not api_key:
        return {"error": "Shodan API key required"}
    
    query = f"ssl.cert.subject.cn:{domain}"
    
    results = await shodan_search(query, api_key)
    
    return results

