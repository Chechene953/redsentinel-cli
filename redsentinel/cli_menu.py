# redsentinel/cli_menu.py
import argparse
import asyncio
import sys
import time

from redsentinel.recon import crtsh_subdomains
from redsentinel.scanner import scan_ports
from redsentinel.webcheck import fetch_http_info
from redsentinel.tools.nmap_wrapper import nmap_scan_nm
from redsentinel.reporter import render_report
from redsentinel.utils import load_config, now_iso

cfg = load_config()

def print_heading(t):
    print("\n" + "="*len(t))
    print(t)
    print("="*len(t))

async def do_recon(target):
    print_heading(f"Recon: {target}")
    subs = await crtsh_subdomains(target)
    print(f"Found {len(subs)} subdomains")
    for s in subs[:50]:
        print(" -", s)
    return subs

async def do_portscan(targets, ports=None):
    ports = ports or [80, 443, 22, 21, 3306, 6379, 8080, 8443]
    results = {}
    for h in targets:
        print(f"[scan] {h}")
        r = await scan_ports(h, ports)
        results[h] = r
        open_ports = [p for p,o in r.items() if o]
        print("  open:", open_ports)
    return results

async def do_webchecks(hosts):
    import aiohttp
    results = []
    async with aiohttp.ClientSession() as sess:
        for h in hosts:
            url = f"https://{h}"
            print("[http] fetching", url)
            r = await fetch_http_info(url, session=sess)
            results.append(r)
    return results

def build_argparser():
    p = argparse.ArgumentParser(prog="redsentinel", description="RedSentinel automation tool")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("recon", help="recon (crt.sh) subdomains")
    r.add_argument("target", help="target domain")

    s = sub.add_parser("scan", help="quick port scan (tcp connect)")
    s.add_argument("target", help="target domain or host")
    s.add_argument("--ports", help="comma separated ports", default="80,443,22,8080")

    n = sub.add_parser("nmap", help="run nmap wrapper (requires nmap installed)")
    n.add_argument("target", help="target domain or comma-separated hosts")
    n.add_argument("--args", help="nmap args override", default=None)

    w = sub.add_parser("webcheck", help="simple http checks")
    w.add_argument("target", help="target host")

    m = sub.add_parser("menu", help="interactive menu")

    return p

def interactive_menu():
    loop = asyncio.get_event_loop()
    while True:
        print("\nRedSentinel — Menu")
        print("1) Recon (crt.sh)")
        print("2) Quick port scan")
        print("3) Nmap scan")
        print("4) Web checks")
        print("5) Generate HTML report (basic)")
        print("0) Quit")
        try:
            choice = input("Choix > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "0":
            return
        target = input("Target (ex: example.com) > ").strip()
        if not target:
            print("Target requis")
            continue

        if choice == "1":
            loop.run_until_complete(do_recon(target))
        elif choice == "2":
            ports_s = input("Ports (comma) [80,443,22] > ").strip() or "80,443,22"
            ports = [int(p.strip()) for p in ports_s.split(",") if p.strip()]
            subs = loop.run_until_complete(do_recon(target))
            hosts = [target] + subs[:20]
            loop.run_until_complete(do_portscan(hosts, ports))
        elif choice == "3":
            args = input("Nmap args (enter for defaults) > ").strip() or None
            hosts = [target]
            print("Lancement nmap (cela utilise python-nmap wrapper).")
            res = nmap_scan_nm(hosts, args=args or cfg.get("tools",{}).get("nmap",{}).get("args","-sC -sV -T4"), dry_run=cfg.get("execution",{}).get("dry_run", True))
            print("Result:", res if isinstance(res, dict) else str(res))
        elif choice == "4":
            loop.run_until_complete(do_webchecks([target]))
        elif choice == "5":
            subs = loop.run_until_complete(do_recon(target))
            hosts = [target] + subs[:20]
            ports_res = loop.run_until_complete(do_portscan(hosts))
            http = loop.run_until_complete(do_webchecks(hosts))
            html = render_report(target, subs, ports_res.get(target, {}), http)
            fn = f"report_{target}.html"
            with open(fn, "w", encoding="utf-8") as f:
                f.write(html)
            print("Report saved to", fn)
        else:
            print("Choice invalide")

def main():
    parser = build_argparser()
    args = parser.parse_args()
    if args.cmd is None:
        interactive_menu()
        return

    loop = asyncio.get_event_loop()
    if args.cmd == "recon":
        loop.run_until_complete(do_recon(args.target))
    elif args.cmd == "scan":
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
        subs = loop.run_until_complete(do_recon(args.target))
        hosts = [args.target] + subs[:20]
        loop.run_until_complete(do_portscan(hosts, ports))
    elif args.cmd == "nmap":
        hosts = args.target.split(",")
        nmap_args = args.args or cfg.get("tools",{}).get("nmap",{}).get("args", "-sC -sV -T4")
        res = nmap_scan_nm(hosts, args=nmap_args, dry_run=cfg.get("execution",{}).get("dry_run", True))
        print(res)
    elif args.cmd == "webcheck":
        loop.run_until_complete(do_webchecks([args.target]))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
