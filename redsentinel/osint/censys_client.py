# redsentinel/osint/censys_client.py
import aiohttp
import logging

logger = logging.getLogger(__name__)


async def censys_search_host(ip, api_id, api_secret):
    """
    Search for IP information on Censys
    
    Args:
        ip: IP address
        api_id: Censys API ID
        api_secret: Censys API Secret
    
    Returns:
        dict with host information
    """
    if not api_id or not api_secret:
        return {"error": "Censys API credentials required"}
    
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    
    # Censys uses basic auth
    auth = aiohttp.BasicAuth(api_id, api_secret)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, auth=auth, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"Censys error: {e}")
        return {"error": str(e)}


async def censys_certificate_search(domain, api_id, api_secret):
    """
    Search for SSL certificates on Censys
    
    Args:
        domain: Domain to search
        api_id: Censys API ID
        api_secret: Censys API Secret
    
    Returns:
        dict with certificate results
    """
    if not api_id or not api_secret:
        return {"error": "Censys API credentials required"}
    
    url = "https://search.censys.io/api/v2/certificates/search"
    auth = aiohttp.BasicAuth(api_id, api_secret)
    
    query = f'parsed.subject_dn="{domain}" OR parsed.names="{domain}"'
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                auth=auth,
                json={"q": query},
                timeout=10
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"error": f"API returned status {resp.status}"}
    except Exception as e:
        logger.error(f"Censys certificate search error: {e}")
        return {"error": str(e)}

