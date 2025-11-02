# redsentinel/ai/discovery.py
"""
AI-powered automated discovery and recommendation engine
Uses pattern recognition and machine learning concepts
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class PatternRecognizer:
    """Recognize patterns in discovered assets"""
    
    def __init__(self):
        self.patterns = {
            "common_subdomain_patterns": [
                r"^(www|mail|ftp|admin|api|cdn|static|assets|dev|test|staging)\.",
                r"\.(internal|local|dev|test|staging|prod)$",
                r"^([a-z]+)-(\d+)(-[a-z]+)?\."
            ],
            "technology_indicators": {
                "wordpress": ["wp-content", "wp-includes", "xmlrpc.php"],
                "joomla": ["joomla", "administrator"],
                "drupal": ["drupal.js", "sites/default"],
                "apache": ["Server: Apache"],
                "nginx": ["Server: nginx"],
                "iis": ["Server: Microsoft-IIS"],
                "php": ["X-Powered-By: PHP"],
                "asp": ["X-Powered-By: ASP.NET"]
            }
        }
    
    def analyze_subdomains(self, subdomains):
        """
        Analyze subdomains for patterns
        
        Args:
            subdomains: List of subdomains
        
        Returns:
            dict with pattern analysis
        """
        analysis = {
            "total": len(subdomains),
            "patterns_detected": {},
            "recommendations": []
        }
        
        # Check for common patterns
        for pattern_name, patterns in self.patterns["common_subdomain_patterns"].items():
            matches = []
            for sub in subdomains:
                for pattern in patterns:
                    if re.search(pattern, sub):
                        matches.append(sub)
                        break
            
            if matches:
                analysis["patterns_detected"][pattern_name] = matches
        
        # Generate recommendations
        if analysis["patterns_detected"].get("common_subdomain_patterns"):
            analysis["recommendations"].append(
                "Common naming pattern detected - try brute force with these patterns"
            )
        
        return analysis
    
    def detect_technology_stack(self, http_headers, content):
        """
        Detect technology stack from HTTP response
        
        Args:
            http_headers: Dict of HTTP headers
            content: HTML/response content
        
        Returns:
            dict with detected technologies
        """
        detected = {
            "web_server": None,
            "cms": None,
            "language": None,
            "frameworks": []
        }
        
        # Check headers
        server_header = http_headers.get("Server", "")
        powered_by = http_headers.get("X-Powered-By", "")
        
        # Detect web server
        for server, indicator in self.patterns["technology_indicators"].items():
            if server in server_header.lower():
                detected["web_server"] = server
                break
        
        # Detect CMS
        content_lower = content.lower()
        for cms, indicators in self.patterns["technology_indicators"].items():
            if any(ind in content_lower for ind in indicators):
                detected["cms"] = cms
                break
        
        # Detect language
        if "php" in powered_by.lower():
            detected["language"] = "PHP"
        elif "asp" in powered_by.lower() or "aspx" in content_lower:
            detected["language"] = "ASP.NET"
        
        return detected


class SmartRecommendation:
    """Generate smart recommendations based on findings"""
    
    def __init__(self):
        self.recommendations_db = {
            "vulnerabilities": {
                "wordpress": ["Check for outdated plugins", "Run wpscan", "Check for exposed wp-admin"],
                "joomla": ["Check for vulnerable components", "Run joomscan"],
                "drupal": ["Check for Drupalgeddon vulnerabilities", "Run droopescan"],
                "apache": ["Check for CVE-2021-41773", "Check mod_rewrite configuration"],
                "nginx": ["Check for nginx internal redirect vulnerability"],
            },
            "services": {
                "mysql": ["Try default credentials", "Run SQLMap", "Check for CVE-2019-5418"],
                "ssh": ["Brute force SSH", "Check for weak keys", "Look for known exploits"],
                "ftp": ["Brute force FTP", "Check for anonymous access", "Check vsftpd version"],
                "smb": ["Try null session", "Brute force SMB", "Check for EternalBlue"],
            },
            "ports": {
                "21": ["FTP - Brute force", "Check for anonymous access"],
                "22": ["SSH - Brute force", "Check SSH version"],
                "80": ["HTTP - Web directory brute force", "Check for admin panels"],
                "443": ["HTTPS - SSL certificate analysis", "Check for Heartbleed"],
                "3306": ["MySQL - Brute force", "Check for exposed databases"],
                "3389": ["RDP - Brute force", "Check for BlueKeep"],
                "5432": ["PostgreSQL - Brute force", "Check for exposed databases"],
            }
        }
    
    def generate_recommendations(self, findings):
        """
        Generate smart recommendations based on findings
        
        Args:
            findings: Dict with security findings
        
        Returns:
            list of recommendations
        """
        recommendations = []
        
        # Analyze vulnerabilities
        vulns = findings.get("vulnerabilities", [])
        for vuln in vulns:
            service = vuln.get("service", "").lower()
            if service in self.recommendations_db["vulnerabilities"]:
                recommendations.extend(self.recommendations_db["vulnerabilities"][service])
        
        # Analyze services
        services = findings.get("services", [])
        for service in services:
            service_name = service.get("name", "").lower()
            if service_name in self.recommendations_db["services"]:
                recommendations.extend(self.recommendations_db["services"][service_name])
        
        # Analyze ports
        ports = findings.get("open_ports", [])
        for port_info in ports:
            port = port_info.get("port")
            if port in self.recommendations_db["ports"]:
                recommendations.extend(self.recommendations_db["ports"][port])
        
        # Remove duplicates
        recommendations = list(set(recommendations))
        
        return recommendations
    
    def prioritize_actions(self, recommendations, severity_levels=None):
        """
        Prioritize recommended actions
        
        Args:
            recommendations: List of recommendations
            severity_levels: Optional severity mapping
        
        Returns:
            dict with prioritized actions
        """
        priority = {
            "high": [],
            "medium": [],
            "low": []
        }
        
        # Simple priority rules
        high_priority_keywords = ["exploit", "cve", "vulnerability", "rce", "sql injection"]
        medium_priority_keywords = ["brute force", "check", "scan"]
        
        for rec in recommendations:
            rec_lower = rec.lower()
            if any(keyword in rec_lower for keyword in high_priority_keywords):
                priority["high"].append(rec)
            elif any(keyword in rec_lower for keyword in medium_priority_keywords):
                priority["medium"].append(rec)
            else:
                priority["low"].append(rec)
        
        return priority


class AnomalyDetector:
    """Detect anomalies in discovered assets"""
    
    def __init__(self):
        self.common_ports = [80, 443, 22, 21, 25, 3306, 5432, 3389]
    
    def detect_anomalies(self, assets):
        """
        Detect anomalies in assets
        
        Args:
            assets: Dict with discovered assets
        
        Returns:
            dict with anomalies
        """
        anomalies = {
            "unusual_ports": [],
            "unusual_subdomains": [],
            "version_mismatch": []
        }
        
        # Check for unusual ports
        open_ports = assets.get("open_ports", [])
        for port_info in open_ports:
            port = port_info.get("port")
            if port not in self.common_ports and 1024 <= port <= 65535:
                anomalies["unusual_ports"].append({
                    "port": port,
                    "service": port_info.get("service"),
                    "reason": "Unusual high-numbered port"
                })
        
        # Check for version mismatches
        services = assets.get("services", [])
        known_vulnerable_versions = {
            "apache": ["2.4.49", "2.4.50"],
            "php": ["5.6", "7.0", "7.1"],
            "openssh": ["7.1", "7.2"]
        }
        
        for service in services:
            name = service.get("name", "").lower()
            version = service.get("version", "")
            
            if name in known_vulnerable_versions:
                for vulnerable_version in known_vulnerable_versions[name]:
                    if vulnerable_version in version:
                        anomalies["version_mismatch"].append({
                            "service": name,
                            "version": version,
                            "reason": "Known vulnerable version"
                        })
        
        return anomalies


def automated_discovery_analysis(target_data):
    """
    Automated discovery and analysis
    
    Args:
        target_data: Comprehensive target data
    
    Returns:
        dict with AI-driven analysis
    """
    recognizer = PatternRecognizer()
    recommender = SmartRecommendation()
    detector = AnomalyDetector()
    
    results = {
        "pattern_analysis": {},
        "recommendations": {},
        "anomalies": {},
        "suggested_tools": []
    }
    
    # Analyze subdomains
    if "subdomains" in target_data:
        results["pattern_analysis"]["subdomains"] = recognizer.analyze_subdomains(
            target_data["subdomains"]
        )
    
    # Generate recommendations
    recommendations = recommender.generate_recommendations(target_data)
    results["recommendations"] = recommender.prioritize_actions(recommendations)
    
    # Detect anomalies
    results["anomalies"] = detector.detect_anomalies(target_data)
    
    # Suggest tools based on findings
    tools = ["nmap", "nuclei", "ffuf"]
    if any("wordpress" in str(v) for v in target_data.values()):
        tools.append("wpscan")
    if any("mysql" in str(v) for v in target_data.values()):
        tools.append("sqlmap")
    if results["anomalies"].get("unusual_ports"):
        tools.append("masscan")
    
    results["suggested_tools"] = list(set(tools))
    
    return results


def generate_attack_path(starting_point, discovered_assets):
    """
    Generate attack paths based on discovered assets
    
    Args:
        starting_point: Initial attack vector
        discovered_assets: Dict with all discovered assets
    
    Returns:
        dict with attack paths
    """
    paths = []
    
    # Example: WordPress -> Database -> Lateral movement
    if any("wordpress" in str(a).lower() for a in discovered_assets.values()):
        path = {
            "entry": "WordPress installation",
            "steps": [
                "Run wpscan for vulnerabilities",
                "Check wp-config.php exposure",
                "Try SQL injection in contact forms",
                "Escalate to database access",
                "Attempt lateral movement"
            ],
            "severity": "high"
        }
        paths.append(path)
    
    # Example: Exposed SSH -> Password brute force -> Root access
    if any(port.get("port") == 22 for port in discovered_assets.get("open_ports", [])):
        path = {
            "entry": "Exposed SSH",
            "steps": [
                "Brute force SSH credentials",
                "Check for SSH key exposure",
                "Attempt privilege escalation",
                "Gain root access"
            ],
            "severity": "critical"
        }
        paths.append(path)
    
    return paths

