# redsentinel/tools/cloud_tools.py
import aiohttp
import logging
from redsentinel.tools.external_tool import find_binary, run_command

logger = logging.getLogger(__name__)


async def check_s3_bucket(bucket_name):
    """
    Check if an S3 bucket exists and is publicly accessible
    
    Args:
        bucket_name: Name of the S3 bucket
    
    Returns:
        dict with bucket information
    """
    result = {
        "bucket": bucket_name,
        "exists": False,
        "public": False,
        "listable": False,
        "files": []
    }
    
    # Try different S3 endpoints
    s3_endpoints = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
        f"https://{bucket_name}.s3.us-east-1.amazonaws.com"
    ]
    
    for endpoint in s3_endpoints:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(endpoint, timeout=10) as resp:
                    result["exists"] = True
                    result["public"] = True
                    
                    # Try to list contents
                    if resp.status == 200:
                        result["listable"] = True
                        # Parse XML response if available
                        content = await resp.text()
                        if "<Contents>" in content:
                            result["files"].append("Found files (see full response)")
                        result["endpoint"] = endpoint
                        break
        except Exception:
            continue
    
    return result


def cloudflare_detection(domain):
    """
    Check if a domain is behind Cloudflare
    
    Args:
        domain: Domain to check
    
    Returns:
        dict with Cloudflare detection results
    """
    result = {
        "domain": domain,
        "behind_cloudflare": False,
        "ip_info": None
    }
    
    try:
        import socket
        import dns.resolver
        
        # Check DNS for Cloudflare nameservers
        ns = dns.resolver.resolve(domain, 'NS')
        for nameserver in ns:
            if "cloudflare" in str(nameserver).lower():
                result["behind_cloudflare"] = True
                break
        
        # Alternative: Check A record for Cloudflare IPs
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                # Common Cloudflare IP ranges
                if ip.startswith("104.") or ip.startswith("172."):
                    result["behind_cloudflare"] = True
                    result["ip_info"] = ip
        except Exception:
            pass
            
    except Exception as e:
        logger.error(f"Cloudflare detection error: {e}")
    
    return result


def cloud_provider_detection(domain_or_ip):
    """
    Detect cloud provider for a domain or IP
    
    Args:
        domain_or_ip: Domain or IP address
    
    Returns:
        dict with cloud provider information
    """
    result = {
        "target": domain_or_ip,
        "provider": "Unknown",
        "region": None,
        "ip": None
    }
    
    try:
        import socket
        import dns.resolver
        
        # Resolve IP
        try:
            ip = socket.gethostbyname(domain_or_ip)
            result["ip"] = ip
        except Exception:
            if "." in domain_or_ip and any(c.isdigit() for c in domain_or_ip):
                ip = domain_or_ip
            else:
                return result
        
        # Check for AWS
        if ip.startswith(("54.", "52.", "50.", "34.")):
            result["provider"] = "AWS"
        # Check for Azure
        elif ip.startswith(("40.", "13.", "20.")):
            result["provider"] = "Azure"
        # Check for GCP
        elif ip.startswith("35.") or ip.startswith("146."):
            result["provider"] = "GCP"
        # Check for Cloudflare
        elif ip.startswith("104.") or ip.startswith("172."):
            result["provider"] = "Cloudflare"
        # Check for DigitalOcean
        elif ip.startswith("159.") or ip.startswith("178."):
            result["provider"] = "DigitalOcean"
            
    except Exception as e:
        logger.error(f"Cloud provider detection error: {e}")
    
    return result


async def s3scanner_scan(domain):
    """
    Use s3scanner for S3 bucket enumeration
    
    Args:
        domain: Domain to scan
    
    Returns:
        dict with scan results
    """
    binpath = find_binary("s3scanner")
    if not binpath:
        return {"error": "s3scanner not found. Install: go install github.com/sa7mon/s3scanner@latest"}
    
    cmd = f"{binpath} -o /tmp/s3_results.txt {domain}"
    
    rc, out, err = run_command(cmd, timeout=300, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}


async def cloud_enum_scan(domain):
    """
    Use cloud_enum for cloud service enumeration
    
    Args:
        domain: Domain to enumerate
    
    Returns:
        dict with enumeration results
    """
    binpath = find_binary("cloud_enum")
    if not binpath:
        return {"error": "cloud_enum not found"}
    
    cmd = f"{binpath} -k {domain} -t 50 -l /tmp/cloud_enum_results.txt"
    
    rc, out, err = run_command(cmd, timeout=600, dry_run=False)
    
    return {"rc": rc, "out": out, "err": err}

