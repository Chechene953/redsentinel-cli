# redsentinel/tools/nmap_wrapper.py
import nmap
import logging
import re
from typing import Dict, List, Optional, Union
from redsentinel.tools.external_tool import run_command, find_binary
from redsentinel.core.error_handler import get_error_handler, ErrorContext

logger = logging.getLogger(__name__)
error_handler = get_error_handler()


def nmap_scan_nm(
    hosts: Union[str, List[str]],
    args: str = "-sS -sV -T4",
    ports: Optional[List[int]] = None,
    timeout: int = 300,
    dry_run: bool = False
) -> Dict:
    """
    Run Nmap scan with improved parsing and CVE detection
    
    Args:
        hosts: Host(s) to scan
        args: Nmap arguments
        ports: Specific ports to scan (optional)
        timeout: Timeout in seconds
        dry_run: If True, don't actually run
    
    Returns:
        Dict with scan results including CVE information
    """
    context = ErrorContext("nmap_scan", str(hosts))
    
    nmap_path = find_binary("nmap")
    if not nmap_path:
        logger.warning("nmap binary not found on PATH")
        return {"error": "nmap binary not found"}
    
    if dry_run:
        logger.warning("Dry-run - skipping actual nmap scan for %s", hosts)
        return {"dry_run": True, "hosts": hosts, "args": args}
    
    # Construire la commande avec ports si spécifiés
    if ports:
        ports_str = ",".join(map(str, ports))
        if "-p" not in args:
            args = f"-p {ports_str} {args}"
    
    nm = nmap.PortScanner()
    try:
        hosts_str = ",".join(hosts) if isinstance(hosts, (list, tuple)) else hosts
        nm.scan(hosts=hosts_str, arguments=args)
        
        results = {}
        for h in nm.all_hosts():
            results[h] = {
                "state": nm[h].state(),
                "hostnames": nm[h].hostnames(),
                "protocols": {},
                "os": {},
                "cves": []
            }
            
            # OS detection
            if "osmatch" in nm[h]:
                os_matches = []
                for osmatch in nm[h]["osmatch"]:
                    os_matches.append({
                        "name": osmatch.get("name", ""),
                        "accuracy": osmatch.get("accuracy", ""),
                        "osclass": osmatch.get("osclass", [])
                    })
                results[h]["os"]["matches"] = os_matches
            
            # Ports and services
            for proto in nm[h].all_protocols():
                results[h]["protocols"][proto] = {}
                lports = nm[h][proto].keys()
                for port in sorted(lports):
                    port_info = nm[h][proto][port]
                    results[h]["protocols"][proto][port] = {
                        "state": port_info.get("state", ""),
                        "name": port_info.get("name", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "cpe": port_info.get("cpe", ""),
                        "script": {}
                    }
                    
                    # Extraire CVE depuis les scripts
                    if "script" in port_info:
                        for script_name, script_output in port_info["script"].items():
                            results[h]["protocols"][proto][port]["script"][script_name] = script_output
                            
                            # Chercher CVE dans la sortie
                            cve_pattern = r'CVE-\d{4}-\d{4,7}'
                            cves = re.findall(cve_pattern, str(script_output), re.IGNORECASE)
                            if cves:
                                results[h]["cves"].extend(cves)
        
        # Dédupliquer les CVE
        for h in results:
            results[h]["cves"] = list(set(results[h]["cves"]))
        
        return results
    
    except Exception as e:
        error_handler.handle_error(e, context)
        logger.exception("nmap scan failed: %s", e)
        # Fallback vers commande directe
        hosts_str = ",".join(hosts) if isinstance(hosts, (list, tuple)) else hosts
        cmd = f"nmap {args} {hosts_str}"
        rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
        return {"rc": rc, "out": out, "err": err}


def nmap_vuln_scan(hosts: Union[str, List[str]], ports: Optional[List[int]] = None) -> Dict:
    """
    Run Nmap vulnerability scan with vuln scripts
    
    Args:
        hosts: Host(s) to scan
        ports: Specific ports (optional)
    
    Returns:
        Dict with vulnerability scan results
    """
    args = "-sC -sV -T4 --script vuln,exploit,auth"
    return nmap_scan_nm(hosts, args=args, ports=ports)


def extract_cves_from_nmap(nmap_results: Dict) -> List[str]:
    """
    Extract all CVE IDs from Nmap results
    
    Args:
        nmap_results: Results from nmap_scan_nm
    
    Returns:
        List of unique CVE IDs
    """
    cves = set()
    
    for host, host_data in nmap_results.items():
        if isinstance(host_data, dict):
            # CVE directement dans les résultats
            if "cves" in host_data:
                cves.update(host_data["cves"])
            
            # CVE dans les scripts de ports
            if "protocols" in host_data:
                for proto, ports_data in host_data["protocols"].items():
                    for port, port_data in ports_data.items():
                        if isinstance(port_data, dict) and "script" in port_data:
                            for script_output in port_data["script"].values():
                                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                                found_cves = re.findall(cve_pattern, str(script_output), re.IGNORECASE)
                                cves.update(found_cves)
    
    return sorted(list(cves))
