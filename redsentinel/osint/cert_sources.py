# redsentinel/osint/cert_sources.py
import aiohttp
import asyncio
import logging

logger = logging.getLogger(__name__)


async def certspotter_subdomains(domain, session=None):
    """
    Fetch subdomains from CertSpotter API
    
    Args:
        domain: Domain to query
        session: Optional aiohttp session
    
    Returns:
        list of subdomains
    """
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True
    
    subdomains = []
    url = f"https://certspotter.com/api/v0/certs?domain={domain}"
    
    try:
        async with session.get(url, timeout=20) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            
            for entry in data:
                for name in entry.get("dns_names", []):
                    if domain in name:
                        subdomains.append(name.strip())
    
    except Exception as e:
        logger.error(f"CertSpotter error: {e}")
    finally:
        if close_session:
            await session.close()
    
    return list(set(subdomains))


async def securitytrails_subdomains(domain, api_key=None, session=None):
    """
    Fetch subdomains from SecurityTrails API
    Requires API key
    
    Args:
        domain: Domain to query
        api_key: SecurityTrails API key
        session: Optional aiohttp session
    
    Returns:
        list of subdomains
    """
    if not api_key:
        logger.warning("SecurityTrails API key required")
        return []
    
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True
    
    subdomains = []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    
    try:
        async with session.get(url, headers=headers, timeout=20) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            
            subs = data.get("subdomains", [])
            for sub in subs:
                subdomains.append(f"{sub}.{domain}")
    
    except Exception as e:
        logger.error(f"SecurityTrails error: {e}")
    finally:
        if close_session:
            await session.close()
    
    return list(set(subdomains))


async def urlscan_subdomains(domain, session=None):
    """
    Search for subdomains using URLScan.io
    
    Args:
        domain: Domain to query
        session: Optional aiohttp session
    
    Returns:
        list of subdomains
    """
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True
    
    subdomains = []
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    
    try:
        async with session.get(url, timeout=20) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            
            results = data.get("results", [])
            for result in results:
                page = result.get("page", {})
                url_full = page.get("url", "")
                # Extract subdomain from URL
                if domain in url_full:
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url_full)
                        hostname = parsed.hostname
                        if domain in hostname:
                            subdomains.append(hostname)
                    except Exception:
                        pass
    
    except Exception as e:
        logger.error(f"URLScan error: {e}")
    finally:
        if close_session:
            await session.close()
    
    return list(set(subdomains))


async def all_cert_sources(domain, securitytrails_key=None):
    """
    Fetch subdomains from all certificate transparency sources
    
    Args:
        domain: Domain to query
        securitytrails_key: Optional SecurityTrails API key
    
    Returns:
        dict with results from each source
    """
    results = {
        "crt.sh": [],  # Already implemented in recon.py
        "certspotter": [],
        "securitytrails": [],
        "urlscan": []
    }
    
    async with aiohttp.ClientSession() as session:
        # Fetch from all sources concurrently
        tasks = [
            certspotter_subdomains(domain, session),
            urlscan_subdomains(domain, session)
        ]
        
        if securitytrails_key:
            tasks.append(securitytrails_subdomains(domain, securitytrails_key, session))
        
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        if completed and len(completed) >= 2:
            results["certspotter"] = completed[0] if not isinstance(completed[0], Exception) else []
            results["urlscan"] = completed[1] if not isinstance(completed[1], Exception) else []
            
            if len(completed) >= 3 and securitytrails_key:
                results["securitytrails"] = completed[2] if not isinstance(completed[2], Exception) else []
    
    # Combine all results
    all_subs = set()
    for subs in results.values():
        all_subs.update(subs)
    
    results["all"] = sorted(list(all_subs))
    
    return results

