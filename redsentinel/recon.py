# redsentinel/recon.py
import aiohttp, asyncio
from urllib.parse import quote

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
