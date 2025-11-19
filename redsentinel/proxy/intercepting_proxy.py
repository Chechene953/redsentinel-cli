"""
Intercepting HTTP/HTTPS Proxy
Professional Man-in-the-Middle proxy like Burp Suite

Features:
- HTTP/HTTPS interception
- Request/Response modification
- History tracking
- Certificate generation
- WebSocket support
- HTTP/2 support
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import json
import re
from pathlib import Path

try:
    from mitmproxy import http, ctx
    from mitmproxy.tools import main as mitmproxy_main
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    http = None
    ctx = None

logger = logging.getLogger(__name__)


class ProxyHistory:
    """Store and manage proxy history"""
    
    def __init__(self, max_entries: int = 10000):
        self.max_entries = max_entries
        self.entries: List[Dict[str, Any]] = []
        self._entry_id = 0
    
    def add_entry(self, request: Dict[str, Any], response: Optional[Dict[str, Any]] = None) -> int:
        """Add entry to history"""
        entry_id = self._entry_id
        self._entry_id += 1
        
        entry = {
            'id': entry_id,
            'timestamp': datetime.utcnow().isoformat(),
            'request': request,
            'response': response,
            'duration_ms': 0
        }
        
        self.entries.append(entry)
        
        # Limit size
        if len(self.entries) > self.max_entries:
            self.entries.pop(0)
        
        return entry_id
    
    def update_response(self, entry_id: int, response: Dict[str, Any], duration_ms: float):
        """Update entry with response"""
        for entry in self.entries:
            if entry['id'] == entry_id:
                entry['response'] = response
                entry['duration_ms'] = duration_ms
                break
    
    def get_entry(self, entry_id: int) -> Optional[Dict[str, Any]]:
        """Get entry by ID"""
        for entry in self.entries:
            if entry['id'] == entry_id:
                return entry
        return None
    
    def search(self, query: str, field: str = 'all') -> List[Dict[str, Any]]:
        """Search history"""
        results = []
        
        for entry in self.entries:
            if field == 'all' or field == 'url':
                if 'url' in entry['request'] and query.lower() in entry['request']['url'].lower():
                    results.append(entry)
                    continue
            
            if field == 'all' or field == 'host':
                if 'host' in entry['request'] and query.lower() in entry['request']['host'].lower():
                    results.append(entry)
                    continue
            
            if field == 'all' or field == 'method':
                if 'method' in entry['request'] and query.upper() == entry['request']['method'].upper():
                    results.append(entry)
        
        return results
    
    def filter_by_status(self, status_code: int) -> List[Dict[str, Any]]:
        """Filter by response status code"""
        return [
            entry for entry in self.entries
            if entry.get('response') and entry['response'].get('status_code') == status_code
        ]
    
    def export_to_file(self, filepath: str):
        """Export history to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.entries, f, indent=2)
        logger.info(f"History exported to {filepath}")


class InterceptionRule:
    """Rule for intercepting requests/responses"""
    
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self.url_pattern: Optional[str] = None
        self.method: Optional[str] = None
        self.intercept_request: bool = True
        self.intercept_response: bool = True
    
    def matches(self, request: Dict[str, Any]) -> bool:
        """Check if request matches this rule"""
        if not self.enabled:
            return False
        
        # Check method
        if self.method and request.get('method', '').upper() != self.method.upper():
            return False
        
        # Check URL pattern
        if self.url_pattern:
            url = request.get('url', '')
            if not re.search(self.url_pattern, url):
                return False
        
        return True


class InterceptingProxy:
    """
    Professional HTTP/HTTPS Intercepting Proxy
    Like Burp Suite Proxy
    """
    
    def __init__(self, host: str = '127.0.0.1', port: int = 8080):
        """
        Initialize intercepting proxy
        
        Args:
            host: Proxy host
            port: Proxy port
        """
        self.host = host
        self.port = port
        self.history = ProxyHistory()
        self.interception_enabled = False
        self.interception_rules: List[InterceptionRule] = []
        self.intercepted_requests: Dict[int, Dict[str, Any]] = {}
        self.modification_callbacks: List[Callable] = []
        self.running = False
        
        # Certificate configuration
        self.cert_dir = Path.home() / '.redsentinel' / 'certs'
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        if not MITMPROXY_AVAILABLE:
            logger.error("mitmproxy not installed. Install with: pip install mitmproxy")
    
    def add_interception_rule(self, rule: InterceptionRule):
        """Add interception rule"""
        self.interception_rules.append(rule)
        logger.info(f"Added interception rule: {rule.name}")
    
    def should_intercept(self, request: Dict[str, Any]) -> bool:
        """Check if request should be intercepted"""
        if not self.interception_enabled:
            return False
        
        # Check rules
        for rule in self.interception_rules:
            if rule.matches(request):
                return True
        
        return False
    
    def register_modification_callback(self, callback: Callable):
        """Register callback for request/response modification"""
        self.modification_callbacks.append(callback)
    
    async def intercept_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intercept and potentially modify request
        
        Args:
            request_data: Request data
        
        Returns:
            Modified request data
        """
        logger.info(f"Intercepting request: {request_data.get('method')} {request_data.get('url')}")
        
        # Store for manual modification
        entry_id = self.history.add_entry(request_data)
        self.intercepted_requests[entry_id] = request_data
        
        # Apply modification callbacks
        modified_request = request_data.copy()
        for callback in self.modification_callbacks:
            try:
                modified_request = callback(modified_request, 'request')
            except Exception as e:
                logger.error(f"Error in modification callback: {e}")
        
        return modified_request
    
    async def intercept_response(self, request_data: Dict[str, Any], 
                                response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intercept and potentially modify response
        
        Args:
            request_data: Original request
            response_data: Response data
        
        Returns:
            Modified response data
        """
        logger.info(f"Intercepting response: {response_data.get('status_code')} for {request_data.get('url')}")
        
        # Apply modification callbacks
        modified_response = response_data.copy()
        for callback in self.modification_callbacks:
            try:
                modified_response = callback(modified_response, 'response')
            except Exception as e:
                logger.error(f"Error in modification callback: {e}")
        
        return modified_response
    
    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get proxy history"""
        return self.history.entries[-limit:]
    
    def search_history(self, query: str, field: str = 'all') -> List[Dict[str, Any]]:
        """Search proxy history"""
        return self.history.search(query, field)
    
    def export_history(self, filepath: str):
        """Export history to file"""
        self.history.export_to_file(filepath)
    
    def generate_certificates(self):
        """Generate CA certificate for HTTPS interception"""
        if not MITMPROXY_AVAILABLE:
            logger.error("Cannot generate certificates: mitmproxy not installed")
            return
        
        from mitmproxy.certs import CertStore
        
        try:
            cert_store = CertStore.from_store(
                str(self.cert_dir),
                'redsentinel-ca'
            )
            
            ca_cert_path = self.cert_dir / 'redsentinel-ca-cert.pem'
            
            logger.info(f"CA certificate generated: {ca_cert_path}")
            logger.info("Install this certificate in your browser to intercept HTTPS traffic")
            
            return str(ca_cert_path)
        
        except Exception as e:
            logger.error(f"Error generating certificates: {e}")
            return None
    
    async def start(self):
        """Start proxy server"""
        if not MITMPROXY_AVAILABLE:
            logger.error("Cannot start proxy: mitmproxy not installed")
            return
        
        logger.info(f"Starting intercepting proxy on {self.host}:{self.port}")
        
        try:
            # Generate certificates if not exists
            if not (self.cert_dir / 'redsentinel-ca-cert.pem').exists():
                self.generate_certificates()
            
            # Configure mitmproxy options
            opts = Options()
            opts.listen_host = self.host
            opts.listen_port = self.port
            opts.confdir = str(self.cert_dir)
            
            # Create addon for interception
            addon = ProxyAddon(self)
            
            # Start proxy (this is blocking, should run in separate thread/process)
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(addon)
            
            self.running = True
            logger.info(f"✓ Proxy started: http://{self.host}:{self.port}")
            logger.info(f"✓ CA Certificate: {self.cert_dir / 'redsentinel-ca-cert.pem'}")
            
            await master.run()
        
        except Exception as e:
            logger.error(f"Error starting proxy: {e}")
            self.running = False
    
    def stop(self):
        """Stop proxy server"""
        self.running = False
        logger.info("Proxy stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get proxy statistics"""
        return {
            'running': self.running,
            'host': self.host,
            'port': self.port,
            'history_entries': len(self.history.entries),
            'interception_enabled': self.interception_enabled,
            'interception_rules': len(self.interception_rules),
            'intercepted_requests': len(self.intercepted_requests)
        }


if MITMPROXY_AVAILABLE:
    class ProxyAddon:
        """Mitmproxy addon for interception"""
        
        def __init__(self, proxy: InterceptingProxy):
            self.proxy = proxy
        
        def request(self, flow: http.HTTPFlow):
            """Handle HTTP request"""
            try:
                request_data = {
                    'method': flow.request.method,
                    'url': flow.request.pretty_url,
                    'host': flow.request.host,
                    'port': flow.request.port,
                    'scheme': flow.request.scheme,
                    'path': flow.request.path,
                    'headers': dict(flow.request.headers),
                    'content': flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else '',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Check if should intercept
                if self.proxy.should_intercept(request_data):
                    # Intercept (this is synchronous, in production should be async)
                    modified = asyncio.run(self.proxy.intercept_request(request_data))
                    
                    # Apply modifications
                    if 'headers' in modified:
                        for key, value in modified['headers'].items():
                            flow.request.headers[key] = value
                    
                    if 'content' in modified and modified['content'] != request_data['content']:
                        flow.request.content = modified['content'].encode('utf-8')
                
                # Add to history
                flow.metadata['entry_id'] = self.proxy.history.add_entry(request_data)
                flow.metadata['start_time'] = datetime.utcnow()
            
            except Exception as e:
                logger.error(f"Error handling request: {e}")
        
        def response(self, flow: http.HTTPFlow):
            """Handle HTTP response"""
            try:
                response_data = {
                    'status_code': flow.response.status_code,
                    'reason': flow.response.reason,
                    'headers': dict(flow.response.headers),
                    'content': flow.response.content.decode('utf-8', errors='ignore') if flow.response.content else '',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Calculate duration
                if 'start_time' in flow.metadata:
                    duration = (datetime.utcnow() - flow.metadata['start_time']).total_seconds() * 1000
                else:
                    duration = 0
                
                # Update history
                if 'entry_id' in flow.metadata:
                    self.proxy.history.update_response(
                        flow.metadata['entry_id'],
                        response_data,
                        duration
                    )
                
                # Check if should intercept response
                request_data = {
                    'method': flow.request.method,
                    'url': flow.request.pretty_url,
                    'host': flow.request.host
                }
                
                if self.proxy.should_intercept(request_data):
                    # Intercept response
                    modified = asyncio.run(self.proxy.intercept_response(request_data, response_data))
                    
                    # Apply modifications
                    if 'status_code' in modified and modified['status_code'] != response_data['status_code']:
                        flow.response.status_code = modified['status_code']
                    
                    if 'headers' in modified:
                        for key, value in modified['headers'].items():
                            flow.response.headers[key] = value
                    
                    if 'content' in modified and modified['content'] != response_data['content']:
                        flow.response.content = modified['content'].encode('utf-8')
            
            except Exception as e:
                logger.error(f"Error handling response: {e}")


# Convenience functions
def start_proxy(host: str = '127.0.0.1', port: int = 8080) -> InterceptingProxy:
    """
    Start intercepting proxy
    
    Args:
        host: Proxy host
        port: Proxy port
    
    Returns:
        InterceptingProxy instance
    """
    proxy = InterceptingProxy(host, port)
    return proxy


# Export
__all__ = ['InterceptingProxy', 'InterceptionRule', 'ProxyHistory', 'start_proxy']

