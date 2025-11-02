# redsentinel/tools/ssl_tools.py
import socket
import ssl
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def analyze_tls(host, port=443, timeout=10):
    """
    Analyze TLS/SSL configuration of a host
    
    Args:
        host: Hostname or IP
        port: Port number (default 443)
        timeout: Connection timeout
    
    Returns:
        dict with TLS information
    """
    results = {
        "host": host,
        "port": port,
        "error": None,
        "supported": False,
        "certificate": {},
        "protocols": [],
        "ciphers": []
    }
    
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Wrap with SSL context
        context = ssl.create_default_context()
        
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Get certificate info
            cert = ssock.getpeercert()
            results["supported"] = True
            results["certificate"] = {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "version": cert.get("version"),
                "serialNumber": cert.get("serialNumber"),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "subjectAltName": cert.get("subjectAltName", [])
            }
            
            # Get protocol version
            results["protocols"] = [ssock.version()]
            
            # Get cipher info
            cipher = ssock.cipher()
            if cipher:
                results["ciphers"] = [{
                    "name": cipher[0],
                    "version": cipher[1],
                    "bits": cipher[2]
                }]
    
    except ssl.SSLError as e:
        results["error"] = f"SSL Error: {str(e)}"
    except socket.timeout:
        results["error"] = "Connection timeout"
    except Exception as e:
        results["error"] = f"Error: {str(e)}"
    
    return results


def check_ssl_labs_grade(host):
    """
    Check SSL Labs API for security grade
    Note: This requires the SSL Labs API
    
    Args:
        host: Hostname
    
    Returns:
        dict with SSL Labs results
    """
    import requests
    try:
        api_url = f"https://api.ssllabs.com/api/v3/analyze?host={host}&publish=off&fromCache=on&maxAge=24"
        response = requests.get(api_url, timeout=30)
        if response.status_code == 200:
            return response.json()
        return {"error": f"API returned status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def sslscan_analysis(host, port=443, timeout=300, dry_run=False):
    """
    Run sslscan to analyze SSL/TLS configuration
    
    Args:
        host: Hostname or IP
        port: Port number
        timeout: Timeout in seconds
        dry_run: If True, don't execute
    
    Returns:
        dict with keys: rc, out, err
    """
    from redsentinel.tools.external_tool import find_binary, run_command
    
    binpath = find_binary("sslscan")
    if not binpath:
        return {"error": "sslscan not found. Install with: sudo apt install sslscan"}
    
    cmd = f"{binpath} {host}:{port}"
    
    rc, out, err = run_command(cmd, timeout=timeout, dry_run=dry_run)
    return {"rc": rc, "out": out, "err": err}


async def comprehensive_ssl_analysis(host, port=443):
    """
    Comprehensive SSL/TLS analysis using multiple methods
    
    Args:
        host: Hostname or IP
        port: Port number
    
    Returns:
        dict with comprehensive SSL analysis results
    """
    results = {
        "host": host,
        "port": port,
        "tls_basic": analyze_tls(host, port),
        "sslscan": None,
        "ssl_labs": None
    }
    
    # Try sslscan if available
    sslscan_result = sslscan_analysis(host, port, dry_run=False)
    if sslscan_result.get("rc") == 0:
        results["sslscan"] = sslscan_result
    
    # Try SSL Labs API (optional, may be rate-limited)
    try:
        ssl_labs_result = check_ssl_labs_grade(host)
        if not ssl_labs_result.get("error"):
            results["ssl_labs"] = ssl_labs_result
    except Exception:
        pass
    
    return results

