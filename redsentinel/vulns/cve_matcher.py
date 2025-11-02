# redsentinel/vulns/cve_matcher.py
import aiohttp
import logging
import re

logger = logging.getLogger(__name__)


async def search_cve(service, version):
    """
    Search for CVEs related to a service version
    
    Args:
        service: Service name
        version: Version string
    
    Returns:
        list of CVE information
    """
    results = []
    
    # Try NVD API
    try:
        async with aiohttp.ClientSession() as session:
            # Simple keyword search
            query = f"{service} {version}"
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"keywordSearch": query}
            
            async with session.get(url, params=params, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    for vuln in vulnerabilities:
                        cve_data = vuln.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        description = cve_data.get("descriptions", [{}])[0].get("value", "")
                        
                        # Extract CVSS score
                        metrics = cve_data.get("metrics", {})
                        cvss_score = None
                        severity = None
                        
                        if "cvssMetricV31" in metrics:
                            cvss = metrics["cvssMetricV31"][0]
                            cvss_score = cvss.get("cvssData", {}).get("baseScore")
                        elif "cvssMetricV2" in metrics:
                            cvss = metrics["cvssMetricV2"][0]
                            cvss_score = cvss.get("cvssData", {}).get("baseScore")
                        
                        if cvss_score:
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                        
                        results.append({
                            "id": cve_id,
                            "description": description,
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "service": service,
                            "version": version
                        })
    except Exception as e:
        logger.error(f"CVE search error: {e}")
    
    return results


async def get_cve_details(cve_id):
    """
    Get detailed CVE information
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)
    
    Returns:
        dict with CVE details
    """
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cveId": cve_id}
            
            async with session.get(url, params=params, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("vulnerabilities"):
                        return data["vulnerabilities"][0]
    except Exception as e:
        logger.error(f"CVE details error: {e}")
    
    return None


def extract_version_from_service(service_string):
    """
    Extract version number from service string
    
    Args:
        service_string: Service description (e.g., "Apache 2.4.49")
    
    Returns:
        tuple of (service_name, version)
    """
    # Common version patterns
    version_patterns = [
        r'(\d+\.\d+\.\d+)',  # x.y.z
        r'(\d+\.\d+)',        # x.y
        r'(\d+)'              # x
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, service_string)
        if match:
            version = match.group(1)
            service_name = service_string.split()[0] if service_string.split() else "unknown"
            return (service_name, version)
    
    return (service_string, None)


async def comprehensive_cve_matching(service_info_list):
    """
    Match services to CVEs
    
    Args:
        service_info_list: List of dicts with service info
    
    Returns:
        dict with matched CVEs
    """
    results = {
        "services_matched": 0,
        "total_cves": 0,
        "critical_cves": [],
        "high_cves": [],
        "medium_cves": [],
        "low_cves": [],
        "all_cves": []
    }
    
    for service_info in service_info_list:
        service_name = service_info.get("name", "")
        version = service_info.get("version", "")
        
        if service_name and version:
            cves = await search_cve(service_name, version)
            
            if cves:
                results["services_matched"] += 1
                results["total_cves"] += len(cves)
                
                for cve in cves:
                    results["all_cves"].append(cve)
                    
                    severity = cve.get("severity", "UNKNOWN")
                    if severity == "CRITICAL":
                        results["critical_cves"].append(cve)
                    elif severity == "HIGH":
                        results["high_cves"].append(cve)
                    elif severity == "MEDIUM":
                        results["medium_cves"].append(cve)
                    elif severity == "LOW":
                        results["low_cves"].append(cve)
    
    return results

