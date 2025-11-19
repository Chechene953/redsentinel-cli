"""
Reconnaissance Orchestrator
Coordinates all OSINT and reconnaissance modules for comprehensive intelligence gathering
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ReconOrchestrator:
    """
    Master orchestrator for all reconnaissance activities
    Coordinates 15+ OSINT sources for comprehensive intelligence
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize reconnaissance orchestrator
        
        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.results = {}
    
    async def passive_reconnaissance(self, target: str) -> Dict[str, Any]:
        """
        Perform passive reconnaissance (non-intrusive)
        
        Args:
            target: Target domain or IP
        
        Returns:
            Passive recon results
        """
        logger.info(f"Starting passive reconnaissance on {target}")
        
        results = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'passive',
            'sources': {}
        }
        
        tasks = []
        
        try:
            # 1. Subdomain Enumeration (existing module)
            from redsentinel.osint.advanced.subdomain_advanced import SubdomainEnumerator
            
            async def subdomain_task():
                try:
                    enumerator = SubdomainEnumerator()
                    return await enumerator.enumerate_all_sources(target)
                except Exception as e:
                    logger.error(f"Subdomain enumeration error: {e}")
                    return {}
            
            tasks.append(('subdomains', subdomain_task()))
            
            # 2. Wayback Machine
            try:
                from redsentinel.osint.advanced.wayback_machine import search_wayback
                tasks.append(('wayback', search_wayback(target, limit=100)))
            except Exception as e:
                logger.error(f"Wayback import error: {e}")
            
            # 3. GitHub Reconnaissance
            try:
                from redsentinel.osint.advanced.github_recon import github_reconnaissance
                github_token = self.config.get('github_token')
                tasks.append(('github', github_reconnaissance(target, token=github_token)))
            except Exception as e:
                logger.error(f"GitHub import error: {e}")
            
            # 4. Cloud Asset Discovery
            try:
                from redsentinel.osint.advanced.cloud_assets import discover_cloud_assets
                tasks.append(('cloud_assets', discover_cloud_assets(target)))
            except Exception as e:
                logger.error(f"Cloud assets import error: {e}")
            
            # 5. Email Harvesting
            try:
                from redsentinel.osint.advanced.email_harvesting import harvest_emails
                hunter_key = self.config.get('hunter_api_key')
                clearbit_key = self.config.get('clearbit_api_key')
                tasks.append(('emails', harvest_emails(target, hunter_key, clearbit_key)))
            except Exception as e:
                logger.error(f"Email harvesting import error: {e}")
            
            # 6. Certificate Transparency (existing)
            try:
                from redsentinel.osint.cert_sources import CertSources
                
                async def cert_task():
                    cert_sources = CertSources()
                    return {
                        'crtsh': await cert_sources.query_crtsh(target),
                        'certspotter': await cert_sources.query_certspotter(target)
                    }
                
                tasks.append(('certificates', cert_task()))
            except Exception as e:
                logger.error(f"Certificate sources import error: {e}")
            
            # 7. Shodan (if API key available)
            try:
                shodan_key = self.config.get('shodan_api_key')
                if shodan_key:
                    from redsentinel.osint.shodan_client import ShodanClient
                    
                    async def shodan_task():
                        client = ShodanClient(shodan_key)
                        return await client.search_domain(target)
                    
                    tasks.append(('shodan', shodan_task()))
            except Exception as e:
                logger.error(f"Shodan import error: {e}")
            
            # 8. Censys (if API key available)
            try:
                censys_id = self.config.get('censys_api_id')
                censys_secret = self.config.get('censys_api_secret')
                if censys_id and censys_secret:
                    from redsentinel.osint.censys_client import CensysClient
                    
                    async def censys_task():
                        client = CensysClient(censys_id, censys_secret)
                        return await client.search_domain(target)
                    
                    tasks.append(('censys', censys_task()))
            except Exception as e:
                logger.error(f"Censys import error: {e}")
            
            # Execute all tasks concurrently
            logger.info(f"Executing {len(tasks)} reconnaissance tasks...")
            
            for source_name, task in tasks:
                try:
                    result = await task
                    results['sources'][source_name] = {
                        'status': 'success',
                        'data': result
                    }
                    logger.info(f"✓ {source_name} completed")
                except Exception as e:
                    logger.error(f"✗ {source_name} failed: {e}")
                    results['sources'][source_name] = {
                        'status': 'error',
                        'error': str(e)
                    }
            
            # Aggregate results
            results['summary'] = self._generate_summary(results['sources'])
            
            logger.info(f"Passive reconnaissance complete. {len(results['sources'])} sources queried.")
            
            return results
        
        except Exception as e:
            logger.error(f"Passive reconnaissance error: {e}")
            return results
    
    async def active_reconnaissance(self, target: str) -> Dict[str, Any]:
        """
        Perform active reconnaissance (intrusive)
        
        Args:
            target: Target domain, IP, or URL
        
        Returns:
            Active recon results
        """
        logger.info(f"Starting active reconnaissance on {target}")
        
        results = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'active',
            'components': {}
        }
        
        try:
            # 1. Port Scanning
            try:
                from redsentinel.scanners.port_scanner_pro import PortScannerPro
                
                scanner = PortScannerPro()
                ports_result = await scanner.scan_async(target, ports='1-1000')
                results['components']['port_scan'] = ports_result
                logger.info("✓ Port scan completed")
            except Exception as e:
                logger.error(f"Port scan error: {e}")
                results['components']['port_scan'] = {'error': str(e)}
            
            # 2. Web Crawling
            try:
                from redsentinel.scanners.web_crawler import WebCrawler
                
                crawler = WebCrawler()
                crawl_result = await crawler.crawl_async(f'https://{target}', max_depth=3)
                results['components']['web_crawl'] = crawl_result
                logger.info("✓ Web crawl completed")
            except Exception as e:
                logger.error(f"Web crawl error: {e}")
                results['components']['web_crawl'] = {'error': str(e)}
            
            # 3. Technology Detection
            try:
                from redsentinel.scanners.tech_profiler import TechProfiler
                
                profiler = TechProfiler()
                tech_result = await profiler.analyze_async(f'https://{target}')
                results['components']['technology'] = tech_result
                logger.info("✓ Technology profiling completed")
            except Exception as e:
                logger.error(f"Technology profiling error: {e}")
                results['components']['technology'] = {'error': str(e)}
            
            # 4. WAF Detection
            try:
                from redsentinel.scanners.waf_detector import WAFDetector
                
                detector = WAFDetector()
                waf_result = await detector.detect_async(f'https://{target}')
                results['components']['waf'] = waf_result
                logger.info("✓ WAF detection completed")
            except Exception as e:
                logger.error(f"WAF detection error: {e}")
                results['components']['waf'] = {'error': str(e)}
            
            # 5. SSL/TLS Analysis
            try:
                from redsentinel.tools.ssl_tools import SSLAnalyzer
                
                analyzer = SSLAnalyzer()
                ssl_result = await analyzer.analyze_async(target)
                results['components']['ssl'] = ssl_result
                logger.info("✓ SSL analysis completed")
            except Exception as e:
                logger.error(f"SSL analysis error: {e}")
                results['components']['ssl'] = {'error': str(e)}
            
            logger.info("Active reconnaissance complete")
            
            return results
        
        except Exception as e:
            logger.error(f"Active reconnaissance error: {e}")
            return results
    
    async def comprehensive_reconnaissance(self, target: str, 
                                          passive: bool = True,
                                          active: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive reconnaissance (both passive and active)
        
        Args:
            target: Target domain, IP, or URL
            passive: Enable passive recon
            active: Enable active recon
        
        Returns:
            Complete reconnaissance results
        """
        logger.info(f"="*60)
        logger.info(f"COMPREHENSIVE RECONNAISSANCE: {target}")
        logger.info(f"="*60)
        
        results = {
            'target': target,
            'start_time': datetime.utcnow().isoformat(),
            'passive_recon': {},
            'active_recon': {}
        }
        
        try:
            tasks = []
            
            if passive:
                tasks.append(('passive', self.passive_reconnaissance(target)))
            
            if active:
                tasks.append(('active', self.active_reconnaissance(target)))
            
            # Execute recon phases
            for phase_name, task in tasks:
                try:
                    result = await task
                    if phase_name == 'passive':
                        results['passive_recon'] = result
                    else:
                        results['active_recon'] = result
                except Exception as e:
                    logger.error(f"{phase_name} recon error: {e}")
                    if phase_name == 'passive':
                        results['passive_recon'] = {'error': str(e)}
                    else:
                        results['active_recon'] = {'error': str(e)}
            
            results['end_time'] = datetime.utcnow().isoformat()
            results['status'] = 'completed'
            
            # Generate executive summary
            results['executive_summary'] = self._generate_executive_summary(results)
            
            logger.info(f"="*60)
            logger.info(f"RECONNAISSANCE COMPLETE")
            logger.info(f"="*60)
            
            return results
        
        except Exception as e:
            logger.error(f"Comprehensive reconnaissance error: {e}")
            results['status'] = 'error'
            results['error'] = str(e)
            return results
    
    def _generate_summary(self, sources: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of reconnaissance results"""
        summary = {
            'sources_queried': len(sources),
            'successful': sum(1 for s in sources.values() if s.get('status') == 'success'),
            'failed': sum(1 for s in sources.values() if s.get('status') == 'error'),
            'key_findings': []
        }
        
        # Extract key findings
        for source_name, source_data in sources.items():
            if source_data.get('status') == 'success':
                data = source_data.get('data', {})
                
                if source_name == 'subdomains' and isinstance(data, list):
                    summary['key_findings'].append(f"{len(data)} subdomains discovered")
                
                elif source_name == 'emails' and isinstance(data, dict):
                    email_count = data.get('total_found', 0)
                    if email_count > 0:
                        summary['key_findings'].append(f"{email_count} email addresses found")
                
                elif source_name == 'cloud_assets' and isinstance(data, dict):
                    total = data.get('summary', {}).get('total_found', 0)
                    if total > 0:
                        summary['key_findings'].append(f"{total} cloud assets discovered")
                
                elif source_name == 'github' and isinstance(data, dict):
                    leaks = data.get('leaked_secrets', {})
                    if leaks:
                        summary['key_findings'].append(f"Potential leaks found in GitHub")
        
        return summary
    
    def _generate_executive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of all recon"""
        summary = {
            'target': results.get('target'),
            'duration': 'N/A',
            'phases_completed': [],
            'total_findings': 0,
            'critical_findings': [],
            'recommendations': []
        }
        
        if 'passive_recon' in results and results['passive_recon']:
            summary['phases_completed'].append('Passive Reconnaissance')
            passive_summary = results['passive_recon'].get('summary', {})
            summary['total_findings'] += passive_summary.get('successful', 0)
        
        if 'active_recon' in results and results['active_recon']:
            summary['phases_completed'].append('Active Reconnaissance')
        
        return summary


# Convenience function
async def comprehensive_recon(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Perform comprehensive reconnaissance on target
    
    Args:
        target: Target domain, IP, or URL
        config: Configuration with API keys
    
    Returns:
        Complete reconnaissance results
    """
    orchestrator = ReconOrchestrator(config)
    return await orchestrator.comprehensive_reconnaissance(target)


# Export
__all__ = ['ReconOrchestrator', 'comprehensive_recon']

