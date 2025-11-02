# redsentinel/cli.py
import asyncio, time
from redsentinel.recon import crtsh_subdomains
from redsentinel.scanner import scan_ports
from redsentinel.webcheck import fetch_http_info
from redsentinel.reporter import render_report
from redsentinel.utils import setup_logging, load_config
import aiohttp
import os

setup_logging()
cfg = load_config()

async def run(target):
    print("[*] Recon: crt.sh subdomains")
    subs = await crtsh_subdomains(target)
    print(f"Found {len(subs)} subdomains (showing first 10):", subs[:10])

    hosts = set([target] + subs[:20])

    ports = [80, 443, 22, 21, 3306, 6379, 8080, 8443]

    all_ports = {}
    for host in hosts:
        res = await scan_ports(host, ports)
        all_ports[host] = res

    http_results = []
    async with aiohttp.ClientSession() as sess:
        for host, res in all_ports.items():
            if res.get(80) or res.get(443):
                for scheme in ("https","http"):
                    url = f"{scheme}://{host}"
                    r = await fetch_http_info(url, session=sess)
                    http_results.append(r)
                    break

    html = render_report(target, subs, all_ports.get(target, {}), http_results)
    out = f"report_{target}.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print("[*] Report saved to", out)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m redsentinel.cli target.tld")
        sys.exit(1)
    target = sys.argv[1]
    asyncio.run(run(target))
