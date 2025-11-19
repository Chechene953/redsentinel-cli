"""
RedSentinel - Machine Learning Analyzer
Author: Alexandre Tavares - Redsentinel
Version: 7.0

ML-powered features:
- Anomaly detection in web responses
- False positive reduction
- Smart payload generation
- Attack path prediction
- Vulnerability scoring optimization
"""

import asyncio
import logging
import json
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class MLPrediction:
    """ML prediction result"""
    confidence: float
    prediction: str
    features: Dict[str, float]
    explanation: str


class AnomalyDetector:
    """
    Detect anomalies in HTTP responses using ML
    """
    
    def __init__(self):
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.scaler = StandardScaler()
            self.trained = False
            logger.info("Anomaly detector initialized")
        except ImportError:
            logger.warning("scikit-learn not available, ML features disabled")
            self.model = None
    
    def train(self, normal_responses: List[Dict[str, Any]]):
        """
        Train on normal HTTP responses
        
        Args:
            normal_responses: List of normal response dicts
        """
        if not self.model:
            return
        
        try:
            # Extract features
            features = []
            for response in normal_responses:
                feat = self._extract_features(response)
                features.append(feat)
            
            X = np.array(features)
            
            # Train
            X_scaled = self.scaler.fit_transform(X)
            self.model.fit(X_scaled)
            self.trained = True
            
            logger.info(f"Anomaly detector trained on {len(normal_responses)} samples")
        
        except Exception as e:
            logger.error(f"Training failed: {e}")
    
    def detect_anomaly(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Detect if response is anomalous
        
        Args:
            response: HTTP response dict
        
        Returns:
            (is_anomalous, anomaly_score)
        """
        if not self.model or not self.trained:
            return False, 0.0
        
        try:
            # Extract features
            features = self._extract_features(response)
            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.score_samples(X_scaled)[0]
            
            is_anomalous = (prediction == -1)
            anomaly_score = abs(score)
            
            return is_anomalous, anomaly_score
        
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return False, 0.0
    
    def _extract_features(self, response: Dict[str, Any]) -> List[float]:
        """Extract numerical features from HTTP response"""
        features = []
        
        # Status code
        features.append(response.get('status_code', 200))
        
        # Content length
        content = response.get('content', '')
        features.append(len(content))
        
        # Header count
        headers = response.get('headers', {})
        features.append(len(headers))
        
        # Response time
        features.append(response.get('response_time', 0.0))
        
        # Content characteristics
        features.append(content.count('<'))  # HTML tags
        features.append(content.count('{'))  # JSON braces
        features.append(content.count('error'))  # Error keywords
        features.append(content.count('exception'))
        features.append(content.count('warning'))
        
        # Header characteristics
        features.append(1 if 'Set-Cookie' in headers else 0)
        features.append(1 if 'Location' in headers else 0)
        features.append(1 if 'X-Powered-By' in headers else 0)
        
        return features


class FalsePositiveReducer:
    """
    Reduce false positives using ML classification
    """
    
    def __init__(self):
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
            self.model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            self.scaler = StandardScaler()
            self.trained = False
            logger.info("False positive reducer initialized")
        except ImportError:
            logger.warning("scikit-learn not available")
            self.model = None
    
    def train(
        self,
        vulnerabilities: List[Dict[str, Any]],
        labels: List[int]  # 1 = true positive, 0 = false positive
    ):
        """
        Train classifier on labeled vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dicts
            labels: List of labels (1=TP, 0=FP)
        """
        if not self.model:
            return
        
        try:
            # Extract features
            features = []
            for vuln in vulnerabilities:
                feat = self._extract_vuln_features(vuln)
                features.append(feat)
            
            X = np.array(features)
            y = np.array(labels)
            
            # Train
            X_scaled = self.scaler.fit_transform(X)
            self.model.fit(X_scaled, y)
            self.trained = True
            
            logger.info(f"FP reducer trained on {len(vulnerabilities)} samples")
        
        except Exception as e:
            logger.error(f"Training failed: {e}")
    
    def is_true_positive(self, vulnerability: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Predict if vulnerability is a true positive
        
        Args:
            vulnerability: Vulnerability dict
        
        Returns:
            (is_true_positive, confidence)
        """
        if not self.model or not self.trained:
            return True, 0.5  # Default to true positive if not trained
        
        try:
            # Extract features
            features = self._extract_vuln_features(vulnerability)
            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            is_tp = (prediction == 1)
            confidence = probabilities[prediction]
            
            return is_tp, confidence
        
        except Exception as e:
            logger.error(f"FP prediction failed: {e}")
            return True, 0.5
    
    def _extract_vuln_features(self, vuln: Dict[str, Any]) -> List[float]:
        """Extract features from vulnerability"""
        features = []
        
        # Severity score
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        severity = vuln.get('severity', 'info').lower()
        features.append(severity_map.get(severity, 0))
        
        # CVSS score if available
        features.append(vuln.get('cvss', 0.0))
        
        # Evidence length
        evidence = vuln.get('evidence', '')
        features.append(len(evidence))
        
        # URL characteristics
        url = vuln.get('url', '')
        features.append(url.count('/'))  # Path depth
        features.append(url.count('?'))  # Has params
        features.append(url.count('&'))  # Param count
        
        # Category features (one-hot encoding for common categories)
        category = vuln.get('category', '').lower()
        features.append(1 if 'xss' in category else 0)
        features.append(1 if 'sql' in category else 0)
        features.append(1 if 'injection' in category else 0)
        features.append(1 if 'access' in category else 0)
        
        # CWE presence
        features.append(1 if vuln.get('cwe') else 0)
        
        # Payload characteristics
        payload = vuln.get('payload', '')
        features.append(len(payload))
        features.append(payload.count('<'))
        features.append(payload.count('\''))
        
        return features


class SmartPayloadGenerator:
    """
    Generate context-aware payloads using ML
    """
    
    def __init__(self):
        self.payload_templates = {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><script>alert(1)</script>',
                'javascript:alert(1)',
                '<svg onload=alert(1)>'
            ],
            'sqli': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "admin'--",
                "' OR 1=1--"
            ],
            'command_injection': [
                '; ls -la',
                '| whoami',
                '`id`',
                '$(whoami)',
                '& dir'
            ],
            'path_traversal': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ]
        }
    
    def generate_payloads(
        self,
        vuln_type: str,
        context: Dict[str, Any],
        count: int = 10
    ) -> List[str]:
        """
        Generate context-aware payloads
        
        Args:
            vuln_type: Type of vulnerability (xss, sqli, etc.)
            context: Context information (URL, parameters, etc.)
            count: Number of payloads to generate
        
        Returns:
            List of payloads
        """
        base_payloads = self.payload_templates.get(vuln_type.lower(), [])
        
        # Context-aware mutations
        payloads = []
        
        for payload in base_payloads:
            # Original
            payloads.append(payload)
            
            # URL encoded
            import urllib.parse
            payloads.append(urllib.parse.quote(payload))
            
            # Double URL encoded
            payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # HTML entity encoding (for XSS)
            if vuln_type.lower() == 'xss':
                html_encoded = ''.join(f'&#{ord(c)};' for c in payload)
                payloads.append(html_encoded)
            
            # Case variations
            if len(payload) > 5:
                payloads.append(payload.upper())
                payloads.append(payload.lower())
                # Mixed case
                mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                               for i, c in enumerate(payload))
                payloads.append(mixed)
        
        # Deduplicate and limit
        payloads = list(set(payloads))
        
        return payloads[:count]
    
    def mutate_payload(self, payload: str, technique: str = 'encoding') -> List[str]:
        """
        Mutate payload using various techniques
        
        Args:
            payload: Base payload
            technique: Mutation technique
        
        Returns:
            List of mutated payloads
        """
        mutations = []
        
        if technique == 'encoding':
            import urllib.parse
            
            # URL encoding
            mutations.append(urllib.parse.quote(payload))
            mutations.append(urllib.parse.quote_plus(payload))
            
            # Double encoding
            mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Unicode encoding
            unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
            mutations.append(unicode_encoded)
        
        elif technique == 'case':
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            mutations.append(payload.swapcase())
        
        elif technique == 'comment_injection':
            # SQL comment injection
            parts = payload.split(' ')
            commented = '/**/'.join(parts)
            mutations.append(commented)
        
        elif technique == 'null_bytes':
            mutations.append(payload + '%00')
            mutations.append(payload + '\\x00')
        
        return mutations


class AttackPathPredictor:
    """
    Predict potential attack paths using graph analysis
    """
    
    def __init__(self):
        self.attack_graph = {}
    
    def build_attack_graph(self, vulnerabilities: List[Dict[str, Any]]):
        """
        Build attack graph from vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities
        """
        # Group by host
        hosts = {}
        for vuln in vulnerabilities:
            from urllib.parse import urlparse
            url = vuln.get('url', '')
            host = urlparse(url).netloc
            
            if host not in hosts:
                hosts[host] = []
            hosts[host].append(vuln)
        
        # Build graph
        for host, vulns in hosts.items():
            self.attack_graph[host] = {
                'vulnerabilities': vulns,
                'entry_points': [],
                'pivot_opportunities': [],
                'high_value_targets': []
            }
            
            # Identify entry points (external-facing vulns)
            for vuln in vulns:
                severity = vuln.get('severity', '').lower()
                category = vuln.get('category', '').lower()
                
                if severity in ['critical', 'high']:
                    self.attack_graph[host]['entry_points'].append(vuln)
                
                # Pivot opportunities (e.g., SSRF, RCE)
                if any(keyword in category for keyword in ['ssrf', 'rce', 'command']):
                    self.attack_graph[host]['pivot_opportunities'].append(vuln)
                
                # High-value targets (auth, admin)
                url = vuln.get('url', '')
                if any(keyword in url for keyword in ['/admin', '/login', '/api']):
                    self.attack_graph[host]['high_value_targets'].append(vuln)
    
    def predict_attack_path(self, target_host: str) -> List[Dict[str, Any]]:
        """
        Predict optimal attack path for target
        
        Args:
            target_host: Target hostname
        
        Returns:
            List of attack steps in order
        """
        if target_host not in self.attack_graph:
            return []
        
        graph_data = self.attack_graph[target_host]
        attack_path = []
        
        # Step 1: Initial compromise (entry points)
        if graph_data['entry_points']:
            # Sort by severity
            entry_points = sorted(
                graph_data['entry_points'],
                key=lambda v: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(
                    v.get('severity', 'info').lower(), 0
                ),
                reverse=True
            )
            
            attack_path.append({
                'step': 1,
                'phase': 'Initial Compromise',
                'vulnerability': entry_points[0],
                'objective': 'Gain initial foothold'
            })
        
        # Step 2: Privilege escalation / Lateral movement
        if graph_data['pivot_opportunities']:
            attack_path.append({
                'step': 2,
                'phase': 'Privilege Escalation',
                'vulnerability': graph_data['pivot_opportunities'][0],
                'objective': 'Escalate privileges or pivot'
            })
        
        # Step 3: Access high-value targets
        if graph_data['high_value_targets']:
            attack_path.append({
                'step': 3,
                'phase': 'Objective Completion',
                'vulnerability': graph_data['high_value_targets'][0],
                'objective': 'Access sensitive data/systems'
            })
        
        return attack_path


class MLAnalyzer:
    """
    Main ML analyzer orchestrator
    """
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.fp_reducer = FalsePositiveReducer()
        self.payload_generator = SmartPayloadGenerator()
        self.attack_path_predictor = AttackPathPredictor()
    
    async def analyze_scan_results(
        self,
        vulnerabilities: List[Dict[str, Any]],
        responses: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive ML analysis of scan results
        
        Args:
            vulnerabilities: List of found vulnerabilities
            responses: Optional list of HTTP responses
        
        Returns:
            Dict with analysis results
        """
        logger.info("Starting ML analysis")
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'filtered_vulnerabilities': [],
            'anomalies': [],
            'attack_paths': {},
            'confidence_scores': {}
        }
        
        # False positive reduction
        for vuln in vulnerabilities:
            is_tp, confidence = self.fp_reducer.is_true_positive(vuln)
            
            if is_tp:
                analysis['filtered_vulnerabilities'].append(vuln)
                analysis['confidence_scores'][vuln.get('name', 'unknown')] = confidence
        
        logger.info(f"FP reduction: {len(vulnerabilities)} → {len(analysis['filtered_vulnerabilities'])}")
        
        # Anomaly detection
        if responses:
            for response in responses:
                is_anomalous, score = self.anomaly_detector.detect_anomaly(response)
                
                if is_anomalous:
                    analysis['anomalies'].append({
                        'url': response.get('url'),
                        'anomaly_score': score,
                        'status_code': response.get('status_code')
                    })
        
        # Attack path prediction
        self.attack_path_predictor.build_attack_graph(analysis['filtered_vulnerabilities'])
        
        # Extract unique hosts
        from urllib.parse import urlparse
        hosts = set()
        for vuln in analysis['filtered_vulnerabilities']:
            url = vuln.get('url', '')
            host = urlparse(url).netloc
            if host:
                hosts.add(host)
        
        for host in hosts:
            attack_path = self.attack_path_predictor.predict_attack_path(host)
            if attack_path:
                analysis['attack_paths'][host] = attack_path
        
        return analysis


# Usage example
if __name__ == "__main__":
    async def main():
        analyzer = MLAnalyzer()
        
        # Sample vulnerabilities
        vulns = [
            {
                'name': 'SQL Injection',
                'severity': 'Critical',
                'category': 'A03:2021-Injection',
                'url': 'https://example.com/login?user=admin',
                'cvss': 9.0,
                'evidence': 'Error message: SQL syntax error',
                'cwe': 'CWE-89'
            },
            {
                'name': 'XSS',
                'severity': 'High',
                'category': 'A03:2021-Injection',
                'url': 'https://example.com/search?q=test',
                'cvss': 7.5,
                'evidence': 'Reflected in response',
                'cwe': 'CWE-79'
            }
        ]
        
        # Analyze
        results = await analyzer.analyze_scan_results(vulns)
        
        print(json.dumps(results, indent=2, default=str))
    
    asyncio.run(main())

