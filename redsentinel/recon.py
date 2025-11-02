# redsentinel/recon.py
import aiohttp, asyncio
from urllib.parse import quote
from redsentinel.osint.cert_sources import all_cert_sources, certspotter_subdomains, urlscan_subdomains

async def crtsh_subdomains(domain, session=None):
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    try:
        async with session.get(url, timeout=20) as resp:
            if resp.status != 200:
                return []
            data = await resp.text()
            import json
            entries = json.loads(data)
            subdomains = set()
            for e in entries:
                name = e.get("name_value", "")
                for n in name.splitlines():
                    subdomains.add(n.strip())
            return sorted(subdomains)
    except Exception:
        return []
    finally:
        if close_session:
            await session.close()


async def enhanced_subdomain_enum(domain, use_all_sources=False):
    """
    Enhanced subdomain enumeration using multiple sources
    
    Args:
        domain: Domain to enumerate
        use_all_sources: If True, use all certificate sources
    
    Returns:
        list of unique subdomains
    """
    all_subdomains = set()
    
    # Always use crt.sh (fast and reliable)
    crtsh_subs = await crtsh_subdomains(domain)
    all_subdomains.update(crtsh_subs)
    
    if use_all_sources:
        # Fetch from additional sources
        try:
            cert_sources_result = await all_cert_sources(domain)
            # Combine all results from cert sources
            if cert_sources_result.get("all"):
                all_subdomains.update(cert_sources_result["all"])
        except Exception as e:
            pass  # Continue if extra sources fail
    
    return sorted(list(all_subdomains))
