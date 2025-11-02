# redsentinel/intel/correlation.py
"""
Data correlation engine for RedSentinel
Analyzes and correlates data from multiple sources
"""


class DataCorrelation:
    """Correlate data from multiple sources to build intelligence"""
    
    def __init__(self):
        self.data = {
            "subdomains": [],
            "ips": [],
            "ports": {},
            "services": {},
            "vulnerabilities": [],
            "certificates": [],
            "dns_records": []
        }
    
    def add_subdomain(self, subdomain):
        """Add subdomain to dataset"""
        if subdomain not in self.data["subdomains"]:
            self.data["subdomains"].append(subdomain)
    
    def add_ip(self, ip):
        """Add IP to dataset"""
        if ip not in self.data["ips"]:
            self.data["ips"].append(ip)
    
    def add_port(self, ip, port, service=None):
        """Add port information"""
        if ip not in self.data["ports"]:
            self.data["ports"][ip] = []
        
        port_info = {"port": port, "service": service}
        if port_info not in self.data["ports"][ip]:
            self.data["ports"][ip].append(port_info)
    
    def add_vulnerability(self, vuln_info):
        """Add vulnerability finding"""
        if vuln_info not in self.data["vulnerabilities"]:
            self.data["vulnerabilities"].append(vuln_info)
    
    def add_certificate(self, cert_info):
        """Add certificate information"""
        if cert_info not in self.data["certificates"]:
            self.data["certificates"].append(cert_info)
    
    def correlate_subdomains_to_ips(self):
        """Correlate subdomains to IP addresses"""
        correlation = {}
        for subdomain in self.data["subdomains"]:
            # Find matching IPs (simplified - in real scenario would do DNS lookup)
            correlation[subdomain] = self.data["ips"]
        return correlation
    
    def find_attack_paths(self):
        """Identify potential attack paths based on gathered data"""
        paths = []
        
        # Build potential attack paths
        # Example: Subdomain -> IP -> Open Ports -> Vulnerabilities
        
        for ip, ports in self.data["ports"].items():
            for port_info in ports:
                port = port_info["port"]
                service = port_info.get("service", "unknown")
                
                # Check for vulnerabilities on this service
                vulns_on_service = [
                    v for v in self.data["vulnerabilities"]
                    if service in str(v).lower() or port == v.get("port")
                ]
                
                if vulns_on_service:
                    path = {
                        "target_ip": ip,
                        "entry_point": f"{ip}:{port}",
                        "service": service,
                        "vulnerabilities": vulns_on_service,
                        "severity": "high" if any(v.get("severity") in ["critical", "high"] for v in vulns_on_service) else "medium"
                    }
                    paths.append(path)
        
        return paths
    
    def identify_technologies(self):
        """Identify technologies in use from gathered data"""
        technologies = {
            "webservers": set(),
            "databases": set(),
            "frameworks": set(),
            "cms": set()
        }
        
        # Analyze services to identify technologies
        for ip, ports in self.data["ports"].items():
            for port_info in ports:
                service = port_info.get("service", "").lower()
                
                # Web servers
                if "apache" in service:
                    technologies["webservers"].add("Apache")
                elif "nginx" in service:
                    technologies["webservers"].add("nginx")
                elif "iis" in service:
                    technologies["webservers"].add("Microsoft IIS")
                
                # Databases
                elif "mysql" in service:
                    technologies["databases"].add("MySQL")
                elif "postgresql" in service or "postgres" in service:
                    technologies["databases"].add("PostgreSQL")
                elif "mongodb" in service:
                    technologies["databases"].add("MongoDB")
                elif "redis" in service:
                    technologies["databases"].add("Redis")
                
                # Popular ports
                if port_info["port"] == 3306:
                    technologies["databases"].add("MySQL")
                elif port_info["port"] == 5432:
                    technologies["databases"].add("PostgreSQL")
                elif port_info["port"] == 27017:
                    technologies["databases"].add("MongoDB")
                elif port_info["port"] == 6379:
                    technologies["databases"].add("Redis")
        
        # Convert sets to lists
        return {k: list(v) for k, v in technologies.items()}
    
    def build_asset_map(self):
        """Build comprehensive asset map"""
        asset_map = {
            "summary": {
                "total_subdomains": len(self.data["subdomains"]),
                "total_ips": len(self.data["ips"]),
                "total_open_ports": sum(len(ports) for ports in self.data["ports"].values()),
                "total_vulnerabilities": len(self.data["vulnerabilities"])
            },
            "subdomains": self.data["subdomains"],
            "ip_addresses": self.data["ips"],
            "open_ports": self.data["ports"],
            "vulnerabilities": self.data["vulnerabilities"],
            "attack_paths": self.find_attack_paths(),
            "technologies": self.identify_technologies(),
            "correlations": self.correlate_subdomains_to_ips()
        }
        
        return asset_map
    
    def generate_report(self):
        """Generate correlation report"""
        asset_map = self.build_asset_map()
        
        report = f"""
🔴 RedSentinel Data Correlation Report

📊 Summary:
  - Subdomains: {asset_map['summary']['total_subdomains']}
  - IP Addresses: {asset_map['summary']['total_ips']}
  - Open Ports: {asset_map['summary']['total_open_ports']}
  - Vulnerabilities: {asset_map['summary']['total_vulnerabilities']}

🎯 Technologies Identified:
  - Web Servers: {', '.join(asset_map['technologies']['webservers']) or 'None'}
  - Databases: {', '.join(asset_map['technologies']['databases']) or 'None'}
  - CMS: {', '.join(asset_map['technologies']['cms']) or 'None'}
  - Frameworks: {', '.join(asset_map['technologies']['frameworks']) or 'None'}

🔍 Attack Paths: {len(asset_map['attack_paths'])} identified

📋 Full details available in correlation data.
"""
        
        return {
            "report": report,
            "data": asset_map
        }


def correlate_scan_results(subdomains=None, ips=None, ports=None, vulns=None):
    """
    Quick correlation function
    
    Args:
        subdomains: List of subdomains
        ips: List of IPs
        ports: Dict of IP -> ports
        vulns: List of vulnerabilities
    
    Returns:
        Correlation report
    """
    correlator = DataCorrelation()
    
    if subdomains:
        for sub in subdomains:
            correlator.add_subdomain(sub)
    
    if ips:
        for ip in ips:
            correlator.add_ip(ip)
    
    if ports:
        for ip, port_list in ports.items():
            for port in port_list:
                correlator.add_port(ip, port)
    
    if vulns:
        for vuln in vulns:
            correlator.add_vulnerability(vuln)
    
    return correlator.generate_report()

