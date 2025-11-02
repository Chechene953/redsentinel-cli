# redsentinel/tools/nmap_wrapper.py
import nmap
import logging
from redsentinel.tools.external_tool import run_command, find_binary

logger = logging.getLogger(__name__)

def nmap_scan_nm(hosts, args="-sS -sV -T4", timeout=300, dry_run=False):
    nmap_path = find_binary("nmap")
    if not nmap_path:
        logger.warning("nmap binary not found on PATH")
        return {"error": "nmap binary not found"}
    if dry_run:
        logger.warning("Dry-run - skipping actual nmap scan for %s", hosts)
        return {"dry_run": True, "hosts": hosts, "args": args}

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=",".join(hosts) if isinstance(hosts, (list,tuple)) else hosts, arguments=args)
        results = {}
        for h in nm.all_hosts():
            results[h] = {"state": nm[h].state(), "protocols": {}}
            for proto in nm[h].all_protocols():
                results[h]["protocols"][proto] = {}
                lports = nm[h][proto].keys()
                for port in sorted(lports):
                    results[h]["protocols"][proto][port] = nm[h][proto][port]
        return results
    except Exception as e:
        logger.exception("nmap scan failed: %s", e)
        cmd = f"nmap {args} {' '.join(hosts) if isinstance(hosts,(list,tuple)) else hosts}"
        rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
        return {"rc": rc, "out": out, "err": err}
