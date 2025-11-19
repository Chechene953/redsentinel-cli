"""
RedSentinel - External Tools Integration
Author: Alexandre Tavares - Redsentinel
Version: 7.0

Integrations with external tools:
- OWASP ZAP
- Nessus
- Qualys
- BloodHound
- Burp Suite
- Wireshark/tshark
- Nmap
- SQLMap
"""

import asyncio
import logging
import json
import subprocess
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


@dataclass
class IntegrationConfig:
    """Integration configuration"""
    tool_name: str
    enabled: bool
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    binary_path: Optional[str] = None
    timeout: int = 300


class OWASPZAPIntegration:
    """
    OWASP ZAP integration
    """
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.api_url = config.api_url or 'http://localhost:8080'
        self.api_key = config.api_key
    
    async def start_scan(self, target: str) -> str:
        """
        Start ZAP active scan
        
        Args:
            target: Target URL
        
        Returns:
            Scan ID
        """
        import aiohttp
        
        logger.info(f"Starting ZAP scan on {target}")
        
        try:
            async with aiohttp.ClientSession() as session:
                # Spider first
                async with session.get(
                    f'{self.api_url}/JSON/spider/action/scan/',
                    params={
                        'apikey': self.api_key,
                        'url': target
                    }
                ) as response:
                    spider_result = await response.json()
                    spider_id = spider_result.get('scan')
                
                # Wait for spider to complete
                await self._wait_for_spider(session, spider_id)
                
                # Start active scan
                async with session.get(
                    f'{self.api_url}/JSON/ascan/action/scan/',
                    params={
                        'apikey': self.api_key,
                        'url': target
                    }
                ) as response:
                    scan_result = await response.json()
                    scan_id = scan_result.get('scan')
                
                logger.info(f"ZAP scan started: {scan_id}")
                return scan_id
        
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            raise
    
    async def _wait_for_spider(self, session, spider_id: str):
        """Wait for spider to complete"""
        while True:
            async with session.get(
                f'{self.api_url}/JSON/spider/view/status/',
                params={
                    'apikey': self.api_key,
                    'scanId': spider_id
                }
            ) as response:
                result = await response.json()
                status = int(result.get('status', 0))
                
                if status >= 100:
                    break
                
                await asyncio.sleep(2)
    
    async def get_alerts(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get alerts from ZAP scan
        
        Args:
            scan_id: Scan ID
        
        Returns:
            List of alerts
        """
        import aiohttp
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.api_url}/JSON/core/view/alerts/',
                    params={'apikey': self.api_key}
                ) as response:
                    result = await response.json()
                    alerts = result.get('alerts', [])
                    
                    # Convert to RedSentinel format
                    vulnerabilities = []
                    for alert in alerts:
                        vuln = {
                            'name': alert.get('alert'),
                            'severity': self._map_severity(alert.get('risk')),
                            'category': alert.get('cweid', 'Unknown'),
                            'url': alert.get('url'),
                            'description': alert.get('description'),
                            'solution': alert.get('solution'),
                            'reference': alert.get('reference'),
                            'cwe': f"CWE-{alert.get('cweid')}" if alert.get('cweid') else None,
                            'evidence': alert.get('evidence'),
                            'source': 'OWASP ZAP'
                        }
                        vulnerabilities.append(vuln)
                    
                    return vulnerabilities
        
        except Exception as e:
            logger.error(f"Failed to get ZAP alerts: {e}")
            return []
    
    def _map_severity(self, zap_risk: str) -> str:
        """Map ZAP risk to RedSentinel severity"""
        mapping = {
            'High': 'HIGH',
            'Medium': 'MEDIUM',
            'Low': 'LOW',
            'Informational': 'INFO'
        }
        return mapping.get(zap_risk, 'MEDIUM')


class NessusIntegration:
    """
    Nessus integration
    """
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.api_url = config.api_url or 'https://localhost:8834'
        self.api_key = config.api_key
    
    async def import_scan(self, scan_file: Path) -> List[Dict[str, Any]]:
        """
        Import Nessus scan results (.nessus XML file)
        
        Args:
            scan_file: Path to .nessus file
        
        Returns:
            List of vulnerabilities
        """
        logger.info(f"Importing Nessus scan from {scan_file}")
        
        try:
            tree = ET.parse(scan_file)
            root = tree.getroot()
            
            vulnerabilities = []
            
            for report_host in root.findall('.//ReportHost'):
                host = report_host.get('name')
                
                for report_item in report_host.findall('.//ReportItem'):
                    severity = int(report_item.get('severity', 0))
                    
                    if severity == 0:  # Skip Info
                        continue
                    
                    vuln = {
                        'name': report_item.get('pluginName'),
                        'severity': self._map_severity(severity),
                        'category': report_item.get('pluginFamily'),
                        'host': host,
                        'port': report_item.get('port'),
                        'protocol': report_item.get('protocol'),
                        'description': self._get_text(report_item, 'description'),
                        'solution': self._get_text(report_item, 'solution'),
                        'cve': self._get_text(report_item, 'cve'),
                        'cvss': self._get_text(report_item, 'cvss_base_score'),
                        'plugin_output': self._get_text(report_item, 'plugin_output'),
                        'source': 'Nessus'
                    }
                    
                    vulnerabilities.append(vuln)
            
            logger.info(f"Imported {len(vulnerabilities)} vulnerabilities from Nessus")
            return vulnerabilities
        
        except Exception as e:
            logger.error(f"Failed to import Nessus scan: {e}")
            return []
    
    def _get_text(self, element, tag: str) -> Optional[str]:
        """Get text from XML element"""
        child = element.find(tag)
        return child.text if child is not None else None
    
    def _map_severity(self, nessus_severity: int) -> str:
        """Map Nessus severity to RedSentinel"""
        mapping = {
            4: 'CRITICAL',
            3: 'HIGH',
            2: 'MEDIUM',
            1: 'LOW',
            0: 'INFO'
        }
        return mapping.get(nessus_severity, 'MEDIUM')


class BloodHoundIntegration:
    """
    BloodHound integration for AD enumeration
    """
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.binary_path = config.binary_path or 'bloodhound-python'
    
    async def collect_ad_data(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Collect Active Directory data
        
        Args:
            domain: Domain name
            username: Username
            password: Password
            dc_ip: Domain Controller IP
        
        Returns:
            Collection results
        """
        logger.info(f"Collecting AD data for {domain}")
        
        cmd = [
            self.binary_path,
            '-d', domain,
            '-u', username,
            '-p', password,
            '-c', 'all',
            '--zip'
        ]
        
        if dc_ip:
            cmd.extend(['-dc', dc_ip])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                logger.info("BloodHound collection successful")
                return {
                    'success': True,
                    'output': stdout.decode(),
                    'domain': domain
                }
            else:
                logger.error(f"BloodHound collection failed: {stderr.decode()}")
                return {
                    'success': False,
                    'error': stderr.decode()
                }
        
        except Exception as e:
            logger.error(f"BloodHound execution failed: {e}")
            return {'success': False, 'error': str(e)}


class BurpSuiteIntegration:
    """
    Burp Suite integration
    """
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.api_url = config.api_url or 'http://localhost:1337'
        self.api_key = config.api_key
    
    async def import_proxy_history(self, burp_xml: Path) -> List[Dict[str, Any]]:
        """
        Import Burp Suite proxy history
        
        Args:
            burp_xml: Path to Burp XML export
        
        Returns:
            List of HTTP requests
        """
        logger.info(f"Importing Burp proxy history from {burp_xml}")
        
        try:
            tree = ET.parse(burp_xml)
            root = tree.getroot()
            
            requests = []
            
            for item in root.findall('.//item'):
                time_elem = item.find('time')
                url_elem = item.find('url')
                method_elem = item.find('method')
                status_elem = item.find('status')
                request_elem = item.find('request')
                response_elem = item.find('response')
                
                request_data = {
                    'timestamp': time_elem.text if time_elem is not None else None,
                    'url': url_elem.text if url_elem is not None else None,
                    'method': method_elem.text if method_elem is not None else None,
                    'status': int(status_elem.text) if status_elem is not None else None,
                    'request': self._decode_base64(request_elem.text) if request_elem is not None else None,
                    'response': self._decode_base64(response_elem.text) if response_elem is not None else None,
                    'source': 'Burp Suite'
                }
                
                requests.append(request_data)
            
            logger.info(f"Imported {len(requests)} requests from Burp")
            return requests
        
        except Exception as e:
            logger.error(f"Failed to import Burp history: {e}")
            return []
    
    def _decode_base64(self, data: str) -> str:
        """Decode base64 encoded data"""
        import base64
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            return data


class NmapIntegration:
    """
    Nmap integration
    """
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.binary_path = config.binary_path or 'nmap'
    
    async def scan(
        self,
        target: str,
        scan_type: str = 'default',
        ports: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Nmap scan
        
        Args:
            target: Target IP/hostname
            scan_type: Scan type (default, quick, full, stealth)
            ports: Ports to scan (e.g., "80,443,8080")
        
        Returns:
            Scan results
        """
        logger.info(f"Running Nmap {scan_type} scan on {target}")
        
        # Build command
        cmd = [self.binary_path]
        
        if scan_type == 'quick':
            cmd.extend(['-F'])  # Fast scan
        elif scan_type == 'full':
            cmd.extend(['-p-'])  # All ports
        elif scan_type == 'stealth':
            cmd.extend(['-sS'])  # SYN scan
        
        if ports:
            cmd.extend(['-p', ports])
        
        cmd.extend([
            '-oX', '-',  # XML output to stdout
            '-sV',  # Version detection
            '--script=default',  # Default scripts
            target
        ])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                # Parse XML output
                return self._parse_nmap_xml(stdout.decode())
            else:
                logger.error(f"Nmap scan failed: {stderr.decode()}")
                return {'success': False, 'error': stderr.decode()}
        
        except Exception as e:
            logger.error(f"Nmap execution failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_nmap_xml(self, xml_data: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_data)
            
            results = {
                'success': True,
                'hosts': []
            }
            
            for host in root.findall('.//host'):
                address = host.find('.//address')
                hostnames = host.findall('.//hostname')
                
                host_data = {
                    'ip': address.get('addr') if address is not None else None,
                    'hostnames': [h.get('name') for h in hostnames],
                    'ports': []
                }
                
                for port in host.findall('.//port'):
                    state = port.find('state')
                    service = port.find('service')
                    
                    port_data = {
                        'port': int(port.get('portid')),
                        'protocol': port.get('protocol'),
                        'state': state.get('state') if state is not None else None,
                        'service': service.get('name') if service is not None else None,
                        'version': service.get('version') if service is not None else None
                    }
                    
                    host_data['ports'].append(port_data)
                
                results['hosts'].append(host_data)
            
            return results
        
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return {'success': False, 'error': str(e)}


class SQLMapIntegration:
    """
    SQLMap integration
    """
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.binary_path = config.binary_path or 'sqlmap'
    
    async def test_sql_injection(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test for SQL injection
        
        Args:
            url: Target URL
            data: POST data
            cookie: Cookie value
        
        Returns:
            SQLMap results
        """
        logger.info(f"Testing SQL injection on {url}")
        
        cmd = [
            self.binary_path,
            '-u', url,
            '--batch',  # Non-interactive
            '--output-dir=/tmp/sqlmap',
            '--flush-session'
        ]
        
        if data:
            cmd.extend(['--data', data])
        
        if cookie:
            cmd.extend(['--cookie', cookie])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            output = stdout.decode()
            
            # Parse output for vulnerabilities
            vulnerable = 'is vulnerable' in output.lower()
            
            return {
                'success': True,
                'vulnerable': vulnerable,
                'output': output,
                'url': url
            }
        
        except Exception as e:
            logger.error(f"SQLMap execution failed: {e}")
            return {'success': False, 'error': str(e)}


class IntegrationManager:
    """
    Manage all external tool integrations
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.integrations = {}
        
        # Initialize enabled integrations
        self._init_integrations()
    
    def _init_integrations(self):
        """Initialize all enabled integrations"""
        integrations_config = self.config.get('integrations', {})
        
        # OWASP ZAP
        if integrations_config.get('owasp_zap', {}).get('enabled'):
            zap_config = IntegrationConfig(
                tool_name='OWASP ZAP',
                enabled=True,
                api_url=integrations_config['owasp_zap'].get('api_url'),
                api_key=integrations_config['owasp_zap'].get('api_key')
            )
            self.integrations['zap'] = OWASPZAPIntegration(zap_config)
        
        # Nessus
        if integrations_config.get('nessus', {}).get('enabled'):
            nessus_config = IntegrationConfig(
                tool_name='Nessus',
                enabled=True,
                api_url=integrations_config['nessus'].get('api_url'),
                api_key=integrations_config['nessus'].get('api_key')
            )
            self.integrations['nessus'] = NessusIntegration(nessus_config)
        
        # BloodHound
        if integrations_config.get('bloodhound', {}).get('enabled'):
            bh_config = IntegrationConfig(
                tool_name='BloodHound',
                enabled=True,
                binary_path=integrations_config['bloodhound'].get('binary_path')
            )
            self.integrations['bloodhound'] = BloodHoundIntegration(bh_config)
        
        # Burp Suite
        if integrations_config.get('burp', {}).get('enabled'):
            burp_config = IntegrationConfig(
                tool_name='Burp Suite',
                enabled=True,
                api_url=integrations_config['burp'].get('api_url'),
                api_key=integrations_config['burp'].get('api_key')
            )
            self.integrations['burp'] = BurpSuiteIntegration(burp_config)
        
        # Nmap
        if integrations_config.get('nmap', {}).get('enabled'):
            nmap_config = IntegrationConfig(
                tool_name='Nmap',
                enabled=True,
                binary_path=integrations_config['nmap'].get('binary_path')
            )
            self.integrations['nmap'] = NmapIntegration(nmap_config)
        
        # SQLMap
        if integrations_config.get('sqlmap', {}).get('enabled'):
            sqlmap_config = IntegrationConfig(
                tool_name='SQLMap',
                enabled=True,
                binary_path=integrations_config['sqlmap'].get('binary_path')
            )
            self.integrations['sqlmap'] = SQLMapIntegration(sqlmap_config)
        
        logger.info(f"Initialized {len(self.integrations)} integrations")
    
    def get_integration(self, name: str):
        """Get integration by name"""
        return self.integrations.get(name)
    
    def list_integrations(self) -> List[str]:
        """List all enabled integrations"""
        return list(self.integrations.keys())


# Usage example
if __name__ == "__main__":
    async def main():
        config = {
            'integrations': {
                'owasp_zap': {
                    'enabled': True,
                    'api_url': 'http://localhost:8080',
                    'api_key': 'changeme'
                },
                'nmap': {
                    'enabled': True,
                    'binary_path': 'nmap'
                }
            }
        }
        
        manager = IntegrationManager(config)
        
        print(f"Enabled integrations: {manager.list_integrations()}")
        
        # Test Nmap
        nmap = manager.get_integration('nmap')
        if nmap:
            results = await nmap.scan('127.0.0.1', scan_type='quick')
            print(f"Nmap results: {json.dumps(results, indent=2)}")
    
    asyncio.run(main())

