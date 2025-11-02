# redsentinel/tools/dns_tools.py
from redsentinel.tools.external_tool import find_binary, run_command
import logging

logger = logging.getLogger(__name__)


def dig_lookup(domain, record_type="A", nameserver=None, timeout=30):
    """
    Perform DNS lookup using dig
    
    Args:
        domain: Domain to query
        record_type: DNS record type (A, AAAA, MX, TXT, etc.)
        nameserver: Optional nameserver to use
        timeout: Timeout in seconds
    
    Returns:
        dict with keys: rc, out, err
    """
    binpath = find_binary("dig")
    if not binpath:
        return {"error": "dig binary not found"}
    
    cmd = f"{binpath} {record_type} {domain} +short"
    if nameserver:
        cmd += f" @{nameserver}"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=False)
    return {"rc": rc, "out": out, "err": err}


def dnsrecon_scan(domain, timeout=300, dry_run=False):
    """
    Perform comprehensive DNS enumeration using dnsrecon
    
    Args:
        domain: Domain to enumerate
        timeout: Timeout in seconds
        dry_run: If True, don't execute
    
    Returns:
        dict with keys: rc, out, err
    """
    binpath = find_binary("dnsrecon")
    if not binpath:
        return {"error": "dnsrecon not found. Install with: sudo apt install dnsrecon"}
    
    cmd = f"{binpath} -d {domain} -t std,brt,srv,axfr"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
    return {"rc": rc, "out": out, "err": err}


def fierce_scan(domain, wordlist=None, timeout=300, dry_run=False):
    """
    Perform DNS brute forcing using fierce
    
    Args:
        domain: Domain to enumerate
        wordlist: Optional custom wordlist
        timeout: Timeout in seconds
        dry_run: If True, don't execute
    
    Returns:
        dict with keys: rc, out, err
    """
    binpath = find_binary("fierce")
    if not binpath:
        return {"error": "fierce not found. Install with: sudo apt install fierce"}
    
    cmd = f"{binpath} -dns {domain}"
    if wordlist:
        cmd += f" -wordlist {wordlist}"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
    return {"rc": rc, "out": out, "err": err}


def host_lookup(domain, record_type="A", timeout=30):
    """
    Perform DNS lookup using host command
    
    Args:
        domain: Domain to query
        record_type: DNS record type
        timeout: Timeout in seconds
    
    Returns:
        dict with keys: rc, out, err
    """
    binpath = find_binary("host")
    if not binpath:
        return {"error": "host binary not found"}
    
    cmd = f"{binpath} -t {record_type} {domain}"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=False)
    return {"rc": rc, "out": out, "err": err}


async def comprehensive_dns_enum(domain, tools=["dig", "host"]):
    """
    Perform comprehensive DNS enumeration using multiple tools
    
    Args:
        domain: Domain to enumerate
        tools: List of tools to use
    
    Returns:
        dict with results from all tools
    """
    results = {}
    
    # DNS record types to check
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV"]
    
    if "dig" in tools:
        results["dig"] = {}
        for rtype in record_types:
            dig_result = dig_lookup(domain, rtype)
            if dig_result.get("rc") == 0 and dig_result.get("out"):
                results["dig"][rtype] = dig_result["out"].strip().split("\n")
    
    if "host" in tools:
        results["host"] = {}
        for rtype in record_types:
            host_result = host_lookup(domain, rtype)
            if host_result.get("rc") == 0 and host_result.get("out"):
                results["host"][rtype] = host_result["out"].strip()
    
    if "dnsrecon" in tools:
        dnsrecon_result = dnsrecon_scan(domain)
        results["dnsrecon"] = dnsrecon_result
    
    if "fierce" in tools:
        fierce_result = fierce_scan(domain)
        results["fierce"] = fierce_result
    
    return results

