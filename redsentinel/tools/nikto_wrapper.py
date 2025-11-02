# redsentinel/tools/nikto_wrapper.py
from redsentinel.tools.external_tool import find_binary, run_command
import logging

logger = logging.getLogger(__name__)


def nikto_scan(target_url, output_format="txt", timeout=300, dry_run=False):
    """
    Run Nikto web vulnerability scanner
    
    Args:
        target_url: URL to scan
        output_format: Output format (txt, csv, xml, json)
        timeout: Timeout in seconds
        dry_run: If True, don't execute
    
    Returns:
        dict with keys: rc, out, err
    """
    binpath = find_binary("nikto")
    if not binpath:
        return {"error": "nikto not found. Install with: sudo apt install nikto"}
    
    output_file = f"/tmp/nikto_output.{output_format}"
    cmd = f"{binpath} -h {target_url} -o {output_file} -Format {output_format}"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
    
    return {"rc": rc, "out": out, "err": err, "output_file": output_file if rc == 0 else None}


def parse_nikto_results(output_file):
    """Parse Nikto output file"""
    import os
    if not os.path.exists(output_file):
        return []
    
    results = []
    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
            
        # Basic parsing for TXT format
        current_item = {}
        for line in lines:
            line = line.strip()
            if line.startswith("+ ") and "found" in line.lower():
                # This is a finding
                if current_item:
                    results.append(current_item)
                current_item = {"finding": line.replace("+ ", "")}
            elif line.startswith("+ ") and current_item:
                # Additional info
                if "info" in current_item:
                    current_item["info"] += " " + line.replace("+ ", "")
                else:
                    current_item["info"] = line.replace("+ ", "")
        
        if current_item:
            results.append(current_item)
            
    except Exception as e:
        logger.error(f"Error parsing Nikto output: {e}")
    
    return results

