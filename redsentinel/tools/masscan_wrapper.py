# redsentinel/tools/masscan_wrapper.py
from redsentinel.tools.external_tool import find_binary, run_command
import logging

logger = logging.getLogger(__name__)


def masscan_scan(target, ports="1-65535", rate=1000, exclude=None, timeout=300, dry_run=False):
    """
    Run masscan ultra-fast port scanner
    
    Args:
        target: Target host or CIDR
        ports: Ports to scan (default: 1-65535)
        rate: Scanning rate (packets per second)
        exclude: IPs to exclude
        timeout: Timeout in seconds
        dry_run: If True, don't execute
    
    Returns:
        dict with keys: rc, out, err
    """
    binpath = find_binary("masscan")
    if not binpath:
        return {"error": "masscan not found. Install with: sudo apt install masscan"}
    
    # Masscan requires root privileges
    import os
    if os.geteuid() != 0:
        return {"error": "masscan requires root privileges. Run with sudo"}
    
    cmd = f"{binpath} -p{ports} --rate={rate} {target}"
    
    if exclude:
        cmd += f" --exclude {exclude}"
    
    cmd += " -oJ /tmp/masscan_output.json"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
    
    return {"rc": rc, "out": out, "err": err}


def parse_masscan_json(output_file="/tmp/masscan_output.json"):
    """Parse masscan JSON output"""
    import json
    import os
    
    if not os.path.exists(output_file):
        return []
    
    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
        
        results = []
        for line in lines:
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get("ip"):
                        results.append(data)
                except json.JSONDecodeError:
                    continue
        
        return results
    except Exception as e:
        logger.error(f"Error parsing masscan JSON: {e}")
        return []

