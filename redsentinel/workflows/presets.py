# redsentinel/workflows/presets.py
"""
Pre-defined workflow presets for RedSentinel
"""

WORKFLOWS = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast reconnaissance with basic enumeration",
        "steps": [
            {
                "name": "subdomain_enumeration",
                "tool": "crtsh_subdomains",
                "enabled": True,
                "params": {"domain": "{target}"}
            },
            {
                "name": "quick_port_scan",
                "tool": "scan_ports",
                "enabled": True,
                "params": {"targets": ["{target}"], "ports": [80, 443, 22]}
            },
            {
                "name": "http_checks",
                "tool": "fetch_http_info",
                "enabled": True,
                "params": {"url": "https://{target}"}
            }
        ]
    },
    
    "standard": {
        "name": "Standard Scan",
        "description": "Comprehensive reconnaissance with common checks",
        "steps": [
            {
                "name": "subdomain_enumeration",
                "tool": "enhanced_subdomain_enum",
                "enabled": True,
                "params": {"domain": "{target}", "use_all_sources": True}
            },
            {
                "name": "port_scan",
                "tool": "scan_ports",
                "enabled": True,
                "params": {"targets": ["{target}"], "ports": "common"}
            },
            {
                "name": "nmap_scan",
                "tool": "nmap_scan_nm",
                "enabled": True,
                "params": {"hosts": ["{target}"], "args": "-sC -sV -T4"}
            },
            {
                "name": "http_checks",
                "tool": "fetch_http_info",
                "enabled": True,
                "params": {"url": "https://{target}"}
            },
            {
                "name": "ssl_analysis",
                "tool": "comprehensive_ssl_analysis",
                "enabled": True,
                "params": {"host": "{target}", "port": 443}
            }
        ]
    },
    
    "deep": {
        "name": "Deep Scan",
        "description": "Thorough security assessment with all tools",
        "steps": [
            {
                "name": "subdomain_enumeration",
                "tool": "enhanced_subdomain_enum",
                "enabled": True,
                "params": {"domain": "{target}", "use_all_sources": True}
            },
            {
                "name": "dns_enumeration",
                "tool": "comprehensive_dns_enum",
                "enabled": True,
                "params": {"domain": "{target}"}
            },
            {
                "name": "port_scan",
                "tool": "scan_ports",
                "enabled": True,
                "params": {"targets": ["{target}"], "ports": "all_common"}
            },
            {
                "name": "nmap_scan",
                "tool": "nmap_scan_nm",
                "enabled": True,
                "params": {"hosts": ["{target}"], "args": "-sC -sV -sS -A -T4"}
            },
            {
                "name": "http_checks",
                "tool": "fetch_http_info",
                "enabled": True,
                "params": {"url": "https://{target}"}
            },
            {
                "name": "ssl_analysis",
                "tool": "comprehensive_ssl_analysis",
                "enabled": True,
                "params": {"host": "{target}", "port": 443}
            },
            {
                "name": "directory_bruteforce",
                "tool": "ffuf_scan",
                "enabled": True,
                "params": {"target_url": "https://{target}"}
            },
            {
                "name": "nuclei_scan",
                "tool": "nuclei_scan",
                "enabled": True,
                "params": {"targets": ["{target}"], "args": "-silent"}
            }
        ]
    },
    
    "vulnerability": {
        "name": "Vulnerability Focus",
        "description": "Focus on vulnerability detection",
        "steps": [
            {
                "name": "subdomain_enumeration",
                "tool": "enhanced_subdomain_enum",
                "enabled": True,
                "params": {"domain": "{target}", "use_all_sources": True}
            },
            {
                "name": "nmap_scan",
                "tool": "nmap_scan_nm",
                "enabled": True,
                "params": {"hosts": ["{target}"], "args": "-sV -T4"}
            },
            {
                "name": "nuclei_scan",
                "tool": "nuclei_scan",
                "enabled": True,
                "params": {"targets": ["{target}"], "args": "-silent -severity critical,high"}
            },
            {
                "name": "nikto_scan",
                "tool": "nikto_scan",
                "enabled": True,
                "params": {"target_url": "https://{target}"}
            }
        ]
    }
}


def get_workflow(name):
    """Get workflow preset by name"""
    return WORKFLOWS.get(name.lower())


def list_workflows():
    """List all available workflow presets"""
    return list(WORKFLOWS.keys())


def get_workflow_info(name):
    """Get workflow information"""
    workflow = get_workflow(name)
    if workflow:
        return {
            "name": workflow["name"],
            "description": workflow["description"],
            "steps": len(workflow["steps"])
        }
    return None

