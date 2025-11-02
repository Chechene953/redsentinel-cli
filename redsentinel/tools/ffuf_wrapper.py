# redsentinel/tools/ffuf_wrapper.py
from redsentinel.tools.external_tool import find_binary, run_command
import os
import logging

logger = logging.getLogger(__name__)


def ffuf_scan(target_url, wordlist="/usr/share/wordlists/dirb/common.txt", 
              extensions="", threads=50, rate=None, timeout=300, dry_run=False):
    """
    Execute ffuf directory brute force scan
    
    Args:
        target_url: Base URL to scan (e.g., https://example.com)
        wordlist: Path to wordlist file
        extensions: File extensions to check (e.g., "php,html,js")
        threads: Number of concurrent threads
        rate: Rate limiting (requests per second)
        timeout: Timeout in seconds
        dry_run: If True, don't execute, just return the command
    
    Returns:
        dict with keys: rc, out, err
    """
    binpath = find_binary("ffuf")
    if not binpath:
        return {"error": "ffuf binary not found"}
    
    # Construire la commande ffuf
    cmd = f"{binpath} -u {target_url}/FUZZ"
    
    # Ajouter les options
    if wordlist and os.path.exists(wordlist):
        cmd += f" -w {wordlist}"
    else:
        cmd += " -w /usr/share/wordlists/dirb/common.txt"
    
    if extensions:
        cmd += f" -e {extensions}"
    
    if threads:
        cmd += f" -t {threads}"
    
    if rate:
        cmd += f" -rate {rate}"
    
    # Format JSON pour parsing
    cmd += " -o /tmp/ffuf_output.json -of json"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
    
    return {"rc": rc, "out": out, "err": err}


def parse_ffuf_json(output_file="/tmp/ffuf_output.json"):
    """Parse ffuf JSON output file"""
    import json
    if not os.path.exists(output_file):
        return []
    
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
        results = data.get("results", [])
        return results
    except Exception as e:
        logger.error(f"Error parsing ffuf JSON: {e}")
        return []

