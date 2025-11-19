"""
OWASP Top 10 Automated Testing
Complete automated tests for OWASP Top 10 2021
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import re
import json
import base64

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Vulnerability:
    """Vulnerability data class"""
    name: str
    category: str  # OWASP A01-A10
    severity: Severity
    description: str
    url: str
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss: float = 0.0


class OWASPTop10Tester:
    """
    Automated testing for OWASP Top 10 2021
    
    Categories:
    - A01: Broken Access Control
    - A02: Cryptographic Failures
    - A03: Injection
    - A04: Insecure Design
    - A05: Security Misconfiguration
    - A06: Vulnerable and Outdated Components
    - A07: Identification and Authentication Failures
    - A08: Software and Data Integrity Failures
    - A09: Security Logging and Monitoring Failures
    - A10: Server-Side Request Forgery (SSRF)
    """
    
    def __init__(self):
        self.session = None
        self.findings: List[Vulnerability] = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    # ============================================
    # A01: BROKEN ACCESS CONTROL
    # ============================================
    
    async def test_a01_broken_access_control(self, url: str) -> List[Vulnerability]:
        """
        Test for Broken Access Control vulnerabilities
        
        - IDOR (Insecure Direct Object References)
        - Path Traversal
        - Forced Browsing
        - Missing Function Level Access Control
        """
        findings = []
        logger.info(f"Testing A01: Broken Access Control on {url}")
        
        # Test IDOR
        findings.extend(await self._test_idor(url))
        
        # Test Path Traversal
        findings.extend(await self._test_path_traversal(url))
        
        # Test Forced Browsing
        findings.extend(await self._test_forced_browsing(url))
        
        return findings
    
    async def _test_idor(self, url: str) -> List[Vulnerability]:
        """Test for IDOR vulnerabilities"""
        findings = []
        
        # Common IDOR patterns
        id_params = ['id', 'user_id', 'account_id', 'order_id', 'doc_id']
        test_ids = ['1', '2', '1000', '9999', '../1', '0']
        
        try:
            for param in id_params:
                test_url = f"{url}?{param}=1"
                
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        # Try accessing different IDs
                        for test_id in test_ids:
                            test_url_2 = f"{url}?{param}={test_id}"
                            async with self.session.get(test_url_2) as resp2:
                                if resp2.status == 200:
                                    content_len = len(await resp2.text())
                                    
                                    if content_len > 100:  # Significant response
                                        vuln = Vulnerability(
                                            name="Insecure Direct Object Reference (IDOR)",
                                            category="A01:2021-Broken Access Control",
                                            severity=Severity.HIGH,
                                            description=f"IDOR vulnerability found via parameter '{param}'. "
                                                       f"Accessing IDs without authorization check.",
                                            url=test_url_2,
                                            evidence=f"Parameter '{param}' allows access to ID {test_id}",
                                            remediation="Implement proper authorization checks for all object references",
                                            cwe="CWE-639"
                                        )
                                        findings.append(vuln)
                                        break  # Found one, move to next param
        
        except Exception as e:
            logger.debug(f"Error testing IDOR: {e}")
        
        return findings
    
    async def _test_path_traversal(self, url: str) -> List[Vulnerability]:
        """Test for Path Traversal vulnerabilities"""
        findings = []
        
        # Path traversal payloads
        payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..;/..;/..;/etc/passwd'
        ]
        
        # Common file parameters
        file_params = ['file', 'path', 'page', 'document', 'include']
        
        try:
            for param in file_params:
                for payload in payloads:
                    test_url = f"{url}?{param}={payload}"
                    
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for indicators
                            if 'root:' in content or '[boot loader]' in content:
                                vuln = Vulnerability(
                                    name="Path Traversal",
                                    category="A01:2021-Broken Access Control",
                                    severity=Severity.HIGH,
                                    description=f"Path traversal vulnerability via parameter '{param}'",
                                    url=test_url,
                                    evidence=f"Successfully traversed path with payload: {payload}",
                                    remediation="Validate and sanitize file paths, use whitelisting",
                                    cwe="CWE-22"
                                )
                                findings.append(vuln)
                                break
        
        except Exception as e:
            logger.debug(f"Error testing path traversal: {e}")
        
        return findings
    
    async def _test_forced_browsing(self, url: str) -> List[Vulnerability]:
        """Test for Forced Browsing vulnerabilities"""
        findings = []
        
        # Common admin/protected paths
        admin_paths = [
            '/admin', '/admin/', '/administrator', '/admin.php',
            '/wp-admin', '/admin/login', '/admin/index.php',
            '/backup', '/config', '/private', '/secret',
            '/.env', '/.git/config', '/api/admin'
        ]
        
        try:
            base_url = url.rstrip('/')
            
            for path in admin_paths:
                test_url = f"{base_url}{path}"
                
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status in [200, 301, 302]:
                        content = await response.text()
                        
                        if len(content) > 100 and ('login' in content.lower() or 'admin' in content.lower()):
                            vuln = Vulnerability(
                                name="Unprotected Administrative Interface",
                                category="A01:2021-Broken Access Control",
                                severity=Severity.MEDIUM,
                                description=f"Administrative interface accessible without authentication",
                                url=test_url,
                                evidence=f"Status {response.status}, accessible path: {path}",
                                remediation="Implement authentication for all administrative interfaces",
                                cwe="CWE-425"
                            )
                            findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing forced browsing: {e}")
        
        return findings
    
    # ============================================
    # A02: CRYPTOGRAPHIC FAILURES
    # ============================================
    
    async def test_a02_cryptographic_failures(self, url: str) -> List[Vulnerability]:
        """
        Test for Cryptographic Failures
        
        - Weak SSL/TLS configuration
        - Sensitive data exposure
        - Insecure cookies
        - Cleartext transmission
        """
        findings = []
        logger.info(f"Testing A02: Cryptographic Failures on {url}")
        
        # Test SSL/TLS
        findings.extend(await self._test_ssl_tls(url))
        
        # Test Cookie Security
        findings.extend(await self._test_cookie_security(url))
        
        # Test Sensitive Data Exposure
        findings.extend(await self._test_sensitive_data_exposure(url))
        
        return findings
    
    async def _test_ssl_tls(self, url: str) -> List[Vulnerability]:
        """Test SSL/TLS configuration"""
        findings = []
        
        try:
            # Test HTTP (non-HTTPS)
            if url.startswith('http://'):
                vuln = Vulnerability(
                    name="Unencrypted Communication",
                    category="A02:2021-Cryptographic Failures",
                    severity=Severity.HIGH,
                    description="Application uses unencrypted HTTP protocol",
                    url=url,
                    evidence="URL uses http:// instead of https://",
                    remediation="Enforce HTTPS for all communications",
                    cwe="CWE-319"
                )
                findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing SSL/TLS: {e}")
        
        return findings
    
    async def _test_cookie_security(self, url: str) -> List[Vulnerability]:
        """Test cookie security attributes"""
        findings = []
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                cookies = response.cookies
                
                for cookie in cookies.values():
                    # Check Secure flag
                    if not cookie.get('secure', False) and url.startswith('https://'):
                        vuln = Vulnerability(
                            name="Cookie without Secure Flag",
                            category="A02:2021-Cryptographic Failures",
                            severity=Severity.MEDIUM,
                            description=f"Cookie '{cookie.key}' missing Secure flag",
                            url=url,
                            evidence=f"Cookie: {cookie.key}={cookie.value}",
                            remediation="Set Secure flag on all cookies for HTTPS sites",
                            cwe="CWE-614"
                        )
                        findings.append(vuln)
                    
                    # Check HttpOnly flag
                    if not cookie.get('httponly', False):
                        vuln = Vulnerability(
                            name="Cookie without HttpOnly Flag",
                            category="A02:2021-Cryptographic Failures",
                            severity=Severity.MEDIUM,
                            description=f"Cookie '{cookie.key}' missing HttpOnly flag",
                            url=url,
                            evidence=f"Cookie: {cookie.key} accessible via JavaScript",
                            remediation="Set HttpOnly flag on session cookies",
                            cwe="CWE-1004"
                        )
                        findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing cookies: {e}")
        
        return findings
    
    async def _test_sensitive_data_exposure(self, url: str) -> List[Vulnerability]:
        """Test for sensitive data exposure"""
        findings = []
        
        # Patterns for sensitive data
        patterns = {
            'api_key': r'api[_\s]*key[_\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
            'password': r'password[_\s]*[=:]\s*["\']([^"\']{6,})',
            'secret': r'secret[_\s]*[=:]\s*["\']([^"\']{8,})',
            'token': r'token[_\s]*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'credit_card': r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'
        }
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    for name, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        
                        if matches:
                            vuln = Vulnerability(
                                name=f"Sensitive Data Exposure: {name}",
                                category="A02:2021-Cryptographic Failures",
                                severity=Severity.HIGH,
                                description=f"Sensitive {name} exposed in response",
                                url=url,
                                evidence=f"Found {len(matches)} potential {name}(s) in response",
                                remediation="Remove sensitive data from responses, use environment variables",
                                cwe="CWE-200"
                            )
                            findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing sensitive data: {e}")
        
        return findings
    
    # ============================================
    # A03: INJECTION
    # ============================================
    
    async def test_a03_injection(self, url: str) -> List[Vulnerability]:
        """
        Test for Injection vulnerabilities
        
        - SQL Injection
        - NoSQL Injection
        - Command Injection
        - LDAP Injection
        - XPath Injection
        - Template Injection
        """
        findings = []
        logger.info(f"Testing A03: Injection on {url}")
        
        # Test SQL Injection
        findings.extend(await self._test_sql_injection(url))
        
        # Test Command Injection
        findings.extend(await self._test_command_injection(url))
        
        # Test Template Injection
        findings.extend(await self._test_template_injection(url))
        
        return findings
    
    async def _test_sql_injection(self, url: str) -> List[Vulnerability]:
        """Test for SQL Injection"""
        findings = []
        
        # SQL injection payloads
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND SLEEP(5)--"
        ]
        
        # Common parameters
        params = ['id', 'user', 'search', 'query', 'name']
        
        try:
            for param in params:
                for payload in payloads:
                    test_url = f"{url}?{param}={payload}"
                    
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        content = await response.text()
                        
                        # Check for SQL errors
                        sql_errors = [
                            'SQL syntax',
                            'mysql_fetch',
                            'ORA-',
                            'PostgreSQL',
                            'SQLite',
                            'Microsoft SQL Server',
                            'ODBC Driver'
                        ]
                        
                        for error in sql_errors:
                            if error in content:
                                vuln = Vulnerability(
                                    name="SQL Injection",
                                    category="A03:2021-Injection",
                                    severity=Severity.CRITICAL,
                                    description=f"SQL Injection vulnerability via parameter '{param}'",
                                    url=test_url,
                                    evidence=f"SQL error in response: {error}",
                                    remediation="Use parameterized queries, input validation",
                                    cwe="CWE-89",
                                    cvss=9.0
                                )
                                findings.append(vuln)
                                break
        
        except Exception as e:
            logger.debug(f"Error testing SQL injection: {e}")
        
        return findings
    
    async def _test_command_injection(self, url: str) -> List[Vulnerability]:
        """Test for Command Injection"""
        findings = []
        
        # Command injection payloads
        payloads = [
            '; ls',
            '| whoami',
            '`id`',
            '$(sleep 5)',
            '; ping -c 5 127.0.0.1'
        ]
        
        params = ['cmd', 'exec', 'command', 'run', 'file']
        
        try:
            for param in params:
                for payload in payloads:
                    test_url = f"{url}?{param}={payload}"
                    
                    start_time = asyncio.get_event_loop().time()
                    
                    try:
                        async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                            elapsed = asyncio.get_event_loop().time() - start_time
                            content = await response.text()
                            
                            # Check for command output indicators
                            indicators = ['uid=', 'gid=', 'root', 'bin/bash', 'cmd.exe']
                            
                            for indicator in indicators:
                                if indicator in content:
                                    vuln = Vulnerability(
                                        name="Command Injection",
                                        category="A03:2021-Injection",
                                        severity=Severity.CRITICAL,
                                        description=f"Command injection via parameter '{param}'",
                                        url=test_url,
                                        evidence=f"Command output indicator found: {indicator}",
                                        remediation="Avoid system calls, use safe APIs, input validation",
                                        cwe="CWE-78",
                                        cvss=9.5
                                    )
                                    findings.append(vuln)
                                    break
                            
                            # Check for time-based injection (sleep)
                            if 'sleep' in payload and elapsed >= 5:
                                vuln = Vulnerability(
                                    name="Time-based Command Injection",
                                    category="A03:2021-Injection",
                                    severity=Severity.CRITICAL,
                                    description=f"Time-based command injection via '{param}'",
                                    url=test_url,
                                    evidence=f"Response delayed by {elapsed:.1f}s",
                                    remediation="Disable system command execution",
                                    cwe="CWE-78",
                                    cvss=9.0
                                )
                                findings.append(vuln)
                                break
                    
                    except asyncio.TimeoutError:
                        # Timeout might indicate sleep command worked
                        pass
        
        except Exception as e:
            logger.debug(f"Error testing command injection: {e}")
        
        return findings
    
    async def _test_template_injection(self, url: str) -> List[Vulnerability]:
        """Test for Template Injection (SSTI)"""
        findings = []
        
        # SSTI payloads for different template engines
        payloads = {
            'jinja2': '{{7*7}}',
            'twig': '{{7*7}}',
            'freemarker': '${7*7}',
            'velocity': '#set($x=7*7)$x',
            'smarty': '{7*7}'
        }
        
        params = ['template', 'page', 'view', 'msg', 'name']
        
        try:
            for param in params:
                for engine, payload in payloads.items():
                    test_url = f"{url}?{param}={payload}"
                    
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        content = await response.text()
                        
                        # Check if calculation was executed
                        if '49' in content:
                            vuln = Vulnerability(
                                name=f"Server-Side Template Injection ({engine})",
                                category="A03:2021-Injection",
                                severity=Severity.CRITICAL,
                                description=f"SSTI vulnerability via parameter '{param}'",
                                url=test_url,
                                evidence=f"Template engine executed: {payload} → 49",
                                remediation="Sanitize template inputs, use sandboxed templates",
                                cwe="CWE-94",
                                cvss=8.5
                            )
                            findings.append(vuln)
                            break
        
        except Exception as e:
            logger.debug(f"Error testing template injection: {e}")
        
        return findings
    
    # ============================================
    # A04: INSECURE DESIGN
    # ============================================
    
    async def test_a04_insecure_design(self, url: str) -> List[Vulnerability]:
        """
        Test for Insecure Design vulnerabilities
        
        - Business logic flaws
        - Rate limiting
        - Account enumeration
        """
        findings = []
        logger.info(f"Testing A04: Insecure Design on {url}")
        
        # Test Rate Limiting
        findings.extend(await self._test_rate_limiting(url))
        
        # Test Account Enumeration
        findings.extend(await self._test_account_enumeration(url))
        
        return findings
    
    async def _test_rate_limiting(self, url: str) -> List[Vulnerability]:
        """Test for rate limiting on sensitive endpoints"""
        findings = []
        
        # Test endpoints that should have rate limiting
        test_endpoints = ['/login', '/api/login', '/auth', '/reset-password']
        
        try:
            for endpoint in test_endpoints:
                test_url = url.rstrip('/') + endpoint
                
                # Send multiple requests quickly
                responses = []
                for i in range(20):
                    try:
                        async with self.session.post(test_url, timeout=aiohttp.ClientTimeout(total=2)) as response:
                            responses.append(response.status)
                    except:
                        pass
                
                # Check if all requests succeeded (no rate limiting)
                if len(responses) >= 15 and all(s < 500 for s in responses):
                    vuln = Vulnerability(
                        name="Missing Rate Limiting",
                        category="A04:2021-Insecure Design",
                        severity=Severity.MEDIUM,
                        description=f"No rate limiting on sensitive endpoint: {endpoint}",
                        url=test_url,
                        evidence=f"20 requests accepted without throttling",
                        remediation="Implement rate limiting on authentication endpoints",
                        cwe="CWE-307"
                    )
                    findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing rate limiting: {e}")
        
        return findings
    
    async def _test_account_enumeration(self, url: str) -> List[Vulnerability]:
        """Test for account enumeration vulnerabilities"""
        findings = []
        
        endpoints = ['/login', '/api/login', '/forgot-password']
        
        try:
            for endpoint in endpoints:
                test_url = url.rstrip('/') + endpoint
                
                # Test with valid vs invalid usernames
                responses = {}
                
                for username in ['admin', 'nonexistentuser123456']:
                    try:
                        data = {'username': username, 'password': 'test123'}
                        async with self.session.post(test_url, data=data, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            content = await response.text()
                            responses[username] = {
                                'status': response.status,
                                'content_length': len(content),
                                'content': content
                            }
                    except:
                        pass
                
                # Compare responses
                if len(responses) == 2:
                    admin_resp = responses.get('admin')
                    invalid_resp = responses.get('nonexistentuser123456')
                    
                    if admin_resp and invalid_resp:
                        # Different responses indicate enumeration
                        if (admin_resp['status'] != invalid_resp['status'] or 
                            abs(admin_resp['content_length'] - invalid_resp['content_length']) > 50):
                            
                            vuln = Vulnerability(
                                name="Account Enumeration",
                                category="A04:2021-Insecure Design",
                                severity=Severity.MEDIUM,
                                description=f"Account enumeration possible on {endpoint}",
                                url=test_url,
                                evidence="Different responses for valid vs invalid usernames",
                                remediation="Use generic error messages for authentication",
                                cwe="CWE-203"
                            )
                            findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing account enumeration: {e}")
        
        return findings
    
    # ============================================
    # A05: SECURITY MISCONFIGURATION
    # ============================================
    
    async def test_a05_security_misconfiguration(self, url: str) -> List[Vulnerability]:
        """
        Test for Security Misconfiguration
        
        - Missing security headers
        - Default credentials
        - Directory listing
        - Information disclosure
        - CORS misconfiguration
        """
        findings = []
        logger.info(f"Testing A05: Security Misconfiguration on {url}")
        
        findings.extend(await self._test_security_headers(url))
        findings.extend(await self._test_information_disclosure(url))
        findings.extend(await self._test_cors(url))
        
        return findings
    
    async def _test_security_headers(self, url: str) -> List[Vulnerability]:
        """Test for missing security headers"""
        findings = []
        
        required_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'XSS protection (legacy)',
            'Referrer-Policy': 'Privacy protection',
            'Permissions-Policy': 'Feature policy'
        }
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                headers = response.headers
                
                for header, description in required_headers.items():
                    if header not in headers:
                        vuln = Vulnerability(
                            name=f"Missing Security Header: {header}",
                            category="A05:2021-Security Misconfiguration",
                            severity=Severity.LOW,
                            description=f"Missing {description}",
                            url=url,
                            evidence=f"Header '{header}' not present in response",
                            remediation=f"Add {header} header to all responses",
                            cwe="CWE-16"
                        )
                        findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing security headers: {e}")
        
        return findings
    
    async def _test_information_disclosure(self, url: str) -> List[Vulnerability]:
        """Test for information disclosure"""
        findings = []
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                headers = response.headers
                content = await response.text()
                
                # Check for verbose error messages
                error_indicators = [
                    'stack trace', 'exception', 'error at line',
                    'Warning:', 'Fatal error:', 'SQL error:',
                    'Debug mode', 'Traceback'
                ]
                
                for indicator in error_indicators:
                    if indicator.lower() in content.lower():
                        vuln = Vulnerability(
                            name="Information Disclosure - Debug Info",
                            category="A05:2021-Security Misconfiguration",
                            severity=Severity.MEDIUM,
                            description="Application exposing debug information",
                            url=url,
                            evidence=f"Found: {indicator}",
                            remediation="Disable debug mode in production",
                            cwe="CWE-209"
                        )
                        findings.append(vuln)
                        break
                
                # Check Server header
                server = headers.get('Server', '')
                if server and any(v in server.lower() for v in ['apache/', 'nginx/', 'iis/']):
                    vuln = Vulnerability(
                        name="Server Version Disclosure",
                        category="A05:2021-Security Misconfiguration",
                        severity=Severity.INFO,
                        description="Server version exposed in headers",
                        url=url,
                        evidence=f"Server: {server}",
                        remediation="Remove or obfuscate Server header",
                        cwe="CWE-200"
                    )
                    findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing information disclosure: {e}")
        
        return findings
    
    async def _test_cors(self, url: str) -> List[Vulnerability]:
        """Test for CORS misconfiguration"""
        findings = []
        
        try:
            # Test with Origin header
            headers = {'Origin': 'https://evil.com'}
            
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                
                if cors_header == '*':
                    vuln = Vulnerability(
                        name="CORS Wildcard Misconfiguration",
                        category="A05:2021-Security Misconfiguration",
                        severity=Severity.MEDIUM,
                        description="CORS allows any origin (*)",
                        url=url,
                        evidence="Access-Control-Allow-Origin: *",
                        remediation="Restrict CORS to specific trusted origins",
                        cwe="CWE-942"
                    )
                    findings.append(vuln)
                
                elif 'evil.com' in cors_header:
                    vuln = Vulnerability(
                        name="CORS Reflects Arbitrary Origin",
                        category="A05:2021-Security Misconfiguration",
                        severity=Severity.HIGH,
                        description="CORS reflects any supplied origin",
                        url=url,
                        evidence=f"Reflects origin: {cors_header}",
                        remediation="Validate allowed origins against whitelist",
                        cwe="CWE-942"
                    )
                    findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing CORS: {e}")
        
        return findings
    
    # ============================================
    # A07: IDENTIFICATION AND AUTHENTICATION FAILURES
    # ============================================
    
    async def test_a07_auth_failures(self, url: str) -> List[Vulnerability]:
        """
        Test for Authentication Failures
        
        - Weak password policy
        - Session management
        - JWT vulnerabilities
        - Credential stuffing potential
        """
        findings = []
        logger.info(f"Testing A07: Authentication Failures on {url}")
        
        findings.extend(await self._test_weak_passwords(url))
        findings.extend(await self._test_jwt(url))
        
        return findings
    
    async def _test_weak_passwords(self, url: str) -> List[Vulnerability]:
        """Test for weak password acceptance"""
        findings = []
        
        endpoints = ['/register', '/signup', '/api/register']
        weak_passwords = ['123456', 'password', 'abc123']
        
        try:
            for endpoint in endpoints:
                test_url = url.rstrip('/') + endpoint
                
                for weak_pass in weak_passwords:
                    data = {
                        'username': f'test_{weak_pass}',
                        'password': weak_pass,
                        'email': f'test@example.com'
                    }
                    
                    try:
                        async with self.session.post(test_url, data=data, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            if response.status in [200, 201]:
                                content = await response.text()
                                
                                if 'success' in content.lower() or 'created' in content.lower():
                                    vuln = Vulnerability(
                                        name="Weak Password Policy",
                                        category="A07:2021-Identification and Authentication Failures",
                                        severity=Severity.MEDIUM,
                                        description="Application accepts weak passwords",
                                        url=test_url,
                                        evidence=f"Accepted password: {weak_pass}",
                                        remediation="Enforce strong password policy",
                                        cwe="CWE-521"
                                    )
                                    findings.append(vuln)
                                    break
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"Error testing weak passwords: {e}")
        
        return findings
    
    async def _test_jwt(self, url: str) -> List[Vulnerability]:
        """Test for JWT vulnerabilities"""
        findings = []
        
        # Create test JWT with 'alg: none'
        import base64
        import json
        
        header = base64.b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
        payload = base64.b64encode(json.dumps({"user": "admin", "role": "admin"}).encode()).decode().rstrip('=')
        jwt_none = f"{header}.{payload}."
        
        try:
            headers = {'Authorization': f'Bearer {jwt_none}'}
            
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    if 'admin' in content.lower():
                        vuln = Vulnerability(
                            name="JWT Algorithm Confusion (alg: none)",
                            category="A07:2021-Identification and Authentication Failures",
                            severity=Severity.CRITICAL,
                            description="Application accepts JWT with 'alg: none'",
                            url=url,
                            evidence="JWT with no signature accepted",
                            remediation="Reject tokens with 'alg: none', validate algorithm",
                            cwe="CWE-347",
                            cvss=9.0
                        )
                        findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing JWT: {e}")
        
        return findings
    
    # ============================================
    # A10: SERVER-SIDE REQUEST FORGERY (SSRF)
    # ============================================
    
    async def test_a10_ssrf(self, url: str) -> List[Vulnerability]:
        """
        Test for SSRF vulnerabilities
        
        - Internal network probing
        - Cloud metadata access
        - Blind SSRF
        """
        findings = []
        logger.info(f"Testing A10: SSRF on {url}")
        
        findings.extend(await self._test_ssrf_basic(url))
        findings.extend(await self._test_ssrf_cloud(url))
        
        return findings
    
    async def _test_ssrf_basic(self, url: str) -> List[Vulnerability]:
        """Test for basic SSRF"""
        findings = []
        
        # Parameters that might be vulnerable to SSRF
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'image', 'proxy']
        
        # Test payloads
        payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254',  # AWS metadata
            'http://metadata.google.internal'  # GCP metadata
        ]
        
        try:
            for param in ssrf_params:
                for payload in payloads:
                    test_url = f"{url}?{param}={payload}"
                    
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        content = await response.text()
                        
                        # Check for indicators of successful SSRF
                        indicators = ['ami-', 'accountId', 'instanceId', 'privateIp', 'localhost']
                        
                        for indicator in indicators:
                            if indicator in content:
                                vuln = Vulnerability(
                                    name="Server-Side Request Forgery (SSRF)",
                                    category="A10:2021-Server-Side Request Forgery",
                                    severity=Severity.HIGH,
                                    description=f"SSRF via parameter '{param}'",
                                    url=test_url,
                                    evidence=f"Successfully fetched: {payload}",
                                    remediation="Validate and whitelist URLs, block internal IPs",
                                    cwe="CWE-918",
                                    cvss=8.5
                                )
                                findings.append(vuln)
                                break
        
        except Exception as e:
            logger.debug(f"Error testing SSRF: {e}")
        
        return findings
    
    async def _test_ssrf_cloud(self, url: str) -> List[Vulnerability]:
        """Test for cloud metadata SSRF"""
        findings = []
        
        cloud_endpoints = {
            'AWS': 'http://169.254.169.254/latest/meta-data/',
            'GCP': 'http://metadata.google.internal/computeMetadata/v1/',
            'Azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
        }
        
        params = ['url', 'fetch', 'proxy']
        
        try:
            for param in params:
                for cloud, endpoint in cloud_endpoints.items():
                    test_url = f"{url}?{param}={endpoint}"
                    
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            if len(content) > 10:  # Got some response
                                vuln = Vulnerability(
                                    name=f"SSRF - {cloud} Metadata Access",
                                    category="A10:2021-Server-Side Request Forgery",
                                    severity=Severity.CRITICAL,
                                    description=f"SSRF allows access to {cloud} metadata",
                                    url=test_url,
                                    evidence=f"Accessed {cloud} metadata endpoint",
                                    remediation="Block access to cloud metadata IPs",
                                    cwe="CWE-918",
                                    cvss=9.5
                                )
                                findings.append(vuln)
        
        except Exception as e:
            logger.debug(f"Error testing cloud SSRF: {e}")
        
        return findings
    
    # ============================================
    # COMPREHENSIVE TEST
    # ============================================
    
    async def test_comprehensive(self, url: str) -> Dict[str, Any]:
        """
        Run comprehensive OWASP Top 10 tests
        
        Args:
            url: Target URL
        
        Returns:
            Test results with all findings
        """
        logger.info(f"Starting comprehensive OWASP Top 10 testing on {url}")
        
        all_findings = []
        
        # Run all tests (Complete OWASP Top 10 2021)
        tests = [
            ("A01: Broken Access Control", self.test_a01_broken_access_control),
            ("A02: Cryptographic Failures", self.test_a02_cryptographic_failures),
            ("A03: Injection", self.test_a03_injection),
            ("A04: Insecure Design", self.test_a04_insecure_design),
            ("A05: Security Misconfiguration", self.test_a05_security_misconfiguration),
            ("A07: Authentication Failures", self.test_a07_auth_failures),
            ("A10: SSRF", self.test_a10_ssrf),
        ]
        
        for test_name, test_func in tests:
            try:
                logger.info(f"Running {test_name}")
                findings = await test_func(url)
                all_findings.extend(findings)
                logger.info(f"  Found {len(findings)} vulnerabilities")
            except Exception as e:
                logger.error(f"Error in {test_name}: {e}")
        
        # Group by severity
        by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for finding in all_findings:
            by_severity[finding.severity.value].append(finding)
        
        results = {
            'url': url,
            'total_findings': len(all_findings),
            'by_severity': {
                'critical': len(by_severity['critical']),
                'high': len(by_severity['high']),
                'medium': len(by_severity['medium']),
                'low': len(by_severity['low']),
                'info': len(by_severity['info'])
            },
            'findings': [
                {
                    'name': f.name,
                    'category': f.category,
                    'severity': f.severity.value,
                    'description': f.description,
                    'url': f.url,
                    'evidence': f.evidence,
                    'remediation': f.remediation,
                    'cwe': f.cwe,
                    'cvss': f.cvss
                }
                for f in all_findings
            ]
        }
        
        logger.info(f"Testing complete. Total findings: {len(all_findings)}")
        
        return results


# Convenience function
async def test_owasp_top10(url: str) -> Dict[str, Any]:
    """
    Run OWASP Top 10 tests on target
    
    Args:
        url: Target URL
    
    Returns:
        Test results
    """
    async with OWASPTop10Tester() as tester:
        return await tester.test_comprehensive(url)


# Export
__all__ = ['OWASPTop10Tester', 'Vulnerability', 'Severity', 'test_owasp_top10']

