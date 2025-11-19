"""
HTTP Intruder
Like Burp Suite Intruder - Automated request fuzzing

Attack Types:
- Sniper: Single position, iterate through payloads
- Battering Ram: All positions use same payload
- Pitchfork: Iterate through payload sets in parallel
- Cluster Bomb: All combinations of payload sets

Features:
- Position markers
- Multiple payload sets
- Grep extraction
- Response analysis
- Results comparison
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import re
import copy
from enum import Enum

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Intruder attack types"""
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


class PayloadPosition:
    """Marker for payload insertion position"""
    
    def __init__(self, position_id: int, name: str, value: str = ""):
        self.position_id = position_id
        self.name = name
        self.value = value  # Original value
    
    def __repr__(self):
        return f"<PayloadPosition {self.position_id}: {self.name}>"


class IntruderRequest:
    """Request template with payload positions"""
    
    def __init__(self, base_request: Dict[str, Any]):
        self.base_request = copy.deepcopy(base_request)
        self.positions: List[PayloadPosition] = []
        self.template = None
        self._position_counter = 0
    
    def add_position(self, field: str, start: int, end: int, name: str = None) -> int:
        """
        Add payload position
        
        Args:
            field: Field name (e.g., 'body', 'headers.Authorization')
            start: Start index
            end: End index
            name: Position name
        
        Returns:
            Position ID
        """
        position_id = self._position_counter
        self._position_counter += 1
        
        position_name = name or f"position_{position_id}"
        
        # Extract original value
        value = self._extract_value(field, start, end)
        
        position = PayloadPosition(position_id, position_name, value)
        self.positions.append(position)
        
        logger.info(f"Added position {position_id}: {position_name} in {field}")
        
        return position_id
    
    def _extract_value(self, field: str, start: int, end: int) -> str:
        """Extract original value from position"""
        # Simplified - would need proper parsing
        return f"marker_{start}_{end}"
    
    def generate_request(self, payloads: Dict[int, str]) -> Dict[str, Any]:
        """
        Generate request with payloads inserted
        
        Args:
            payloads: Dictionary of position_id -> payload
        
        Returns:
            Generated request
        """
        request = copy.deepcopy(self.base_request)
        
        # Replace markers with payloads
        # This is simplified - production would need proper template engine
        for position_id, payload in payloads.items():
            # Apply payload to appropriate field
            pass
        
        return request


class IntruderResult:
    """Single intruder attack result"""
    
    def __init__(self, request_num: int, payloads: Dict[int, str], 
                 response: Dict[str, Any]):
        self.request_num = request_num
        self.payloads = payloads
        self.response = response
        self.timestamp = datetime.utcnow()
        self.extracted_data: Dict[str, List[str]] = {}
    
    def extract_data(self, pattern: str, flags: int = 0) -> List[str]:
        """Extract data from response using regex"""
        content = self.response.get('content', '')
        matches = re.findall(pattern, content, flags)
        return matches
    
    def get_status_code(self) -> int:
        """Get response status code"""
        return self.response.get('status_code', 0)
    
    def get_content_length(self) -> int:
        """Get response content length"""
        return len(self.response.get('content', ''))
    
    def get_duration(self) -> float:
        """Get request duration"""
        return self.response.get('duration_ms', 0)


class HTTPIntruder:
    """
    HTTP Intruder - Automated request fuzzing
    Like Burp Suite Intruder
    """
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self._session_counter = 0
    
    def create_session(self, request: Dict[str, Any], attack_type: AttackType = AttackType.SNIPER) -> str:
        """
        Create new intruder session
        
        Args:
            request: Base request
            attack_type: Attack type
        
        Returns:
            Session ID
        """
        session_id = f"intruder_{self._session_counter}"
        self._session_counter += 1
        
        self.sessions[session_id] = {
            'id': session_id,
            'request_template': IntruderRequest(request),
            'attack_type': attack_type,
            'payload_sets': {},
            'results': [],
            'grep_patterns': [],
            'created_at': datetime.utcnow(),
            'status': 'ready'
        }
        
        logger.info(f"Created intruder session: {session_id} ({attack_type.value})")
        
        return session_id
    
    def add_position(self, session_id: str, field: str, start: int, end: int, 
                    name: str = None) -> Optional[int]:
        """Add payload position"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        request_template = session['request_template']
        position_id = request_template.add_position(field, start, end, name)
        
        return position_id
    
    def set_payload_set(self, session_id: str, position_id: int, payloads: List[str]) -> bool:
        """
        Set payload set for position
        
        Args:
            session_id: Session ID
            position_id: Position ID
            payloads: List of payloads
        
        Returns:
            Success status
        """
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        session['payload_sets'][position_id] = payloads
        
        logger.info(f"Set payload set for position {position_id}: {len(payloads)} payloads")
        
        return True
    
    def add_grep_pattern(self, session_id: str, pattern: str, name: str = None) -> bool:
        """Add grep pattern for extraction"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        session['grep_patterns'].append({
            'name': name or pattern,
            'pattern': pattern
        })
        
        return True
    
    async def start_attack(self, session_id: str, max_concurrent: int = 10) -> bool:
        """
        Start intruder attack
        
        Args:
            session_id: Session ID
            max_concurrent: Maximum concurrent requests
        
        Returns:
            Success status
        """
        session = self.sessions.get(session_id)
        if not session:
            logger.error(f"Session not found: {session_id}")
            return False
        
        if session['status'] == 'running':
            logger.warning(f"Attack already running: {session_id}")
            return False
        
        session['status'] = 'running'
        session['results'] = []
        
        try:
            # Generate attack payloads based on attack type
            attack_type = session['attack_type']
            request_template = session['request_template']
            payload_sets = session['payload_sets']
            
            payload_combinations = self._generate_payload_combinations(
                attack_type,
                request_template.positions,
                payload_sets
            )
            
            logger.info(f"Starting attack with {len(payload_combinations)} requests")
            
            # Execute requests with concurrency control
            semaphore = asyncio.Semaphore(max_concurrent)
            
            tasks = []
            for i, payloads in enumerate(payload_combinations):
                task = self._execute_request(session_id, i, payloads, semaphore)
                tasks.append(task)
            
            # Wait for all requests
            await asyncio.gather(*tasks, return_exceptions=True)
            
            session['status'] = 'completed'
            
            logger.info(f"Attack completed: {len(session['results'])} results")
            
            return True
        
        except Exception as e:
            logger.error(f"Error during attack: {e}")
            session['status'] = 'error'
            return False
    
    async def _execute_request(self, session_id: str, request_num: int,
                               payloads: Dict[int, str], semaphore: asyncio.Semaphore):
        """Execute single request with payload"""
        async with semaphore:
            session = self.sessions[session_id]
            request_template = session['request_template']
            
            try:
                # Generate request with payloads
                request = request_template.generate_request(payloads)
                
                # Send request
                response = await self._send_request(request)
                
                # Create result
                result = IntruderResult(request_num, payloads, response)
                
                # Apply grep patterns
                for grep in session['grep_patterns']:
                    extracted = result.extract_data(grep['pattern'])
                    result.extracted_data[grep['name']] = extracted
                
                # Store result
                session['results'].append(result)
                
                # Log progress
                if (request_num + 1) % 10 == 0:
                    logger.info(f"Progress: {request_num + 1} requests completed")
            
            except Exception as e:
                logger.error(f"Error executing request {request_num}: {e}")
    
    async def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send HTTP request"""
        try:
            scheme = request.get('scheme', 'https')
            host = request.get('host', '')
            port = request.get('port', 443 if scheme == 'https' else 80)
            path = request.get('path', '/')
            
            if port in (80, 443):
                url = f"{scheme}://{host}{path}"
            else:
                url = f"{scheme}://{host}:{port}{path}"
            
            method = request.get('method', 'GET')
            headers = request.get('headers', {})
            body = request.get('body', '')
            
            start_time = datetime.utcnow()
            
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body if body else None,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    end_time = datetime.utcnow()
                    duration_ms = (end_time - start_time).total_seconds() * 1000
                    
                    content = await response.text()
                    
                    return {
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'content': content,
                        'duration_ms': duration_ms
                    }
        
        except Exception as e:
            logger.error(f"Request error: {e}")
            return {
                'error': str(e),
                'status_code': 0,
                'content': '',
                'duration_ms': 0
            }
    
    def _generate_payload_combinations(self, attack_type: AttackType,
                                      positions: List[PayloadPosition],
                                      payload_sets: Dict[int, List[str]]) -> List[Dict[int, str]]:
        """Generate payload combinations based on attack type"""
        
        if attack_type == AttackType.SNIPER:
            # Single position, iterate through all payloads
            combinations = []
            for position in positions:
                payloads = payload_sets.get(position.position_id, [])
                for payload in payloads:
                    combinations.append({position.position_id: payload})
            return combinations
        
        elif attack_type == AttackType.BATTERING_RAM:
            # All positions use same payload
            if not positions:
                return []
            
            first_position = positions[0]
            payloads = payload_sets.get(first_position.position_id, [])
            
            combinations = []
            for payload in payloads:
                combo = {pos.position_id: payload for pos in positions}
                combinations.append(combo)
            return combinations
        
        elif attack_type == AttackType.PITCHFORK:
            # Iterate through payload sets in parallel
            if not positions:
                return []
            
            # Get minimum length
            min_length = min(
                len(payload_sets.get(pos.position_id, []))
                for pos in positions
            )
            
            combinations = []
            for i in range(min_length):
                combo = {}
                for pos in positions:
                    payloads = payload_sets.get(pos.position_id, [])
                    if i < len(payloads):
                        combo[pos.position_id] = payloads[i]
                combinations.append(combo)
            
            return combinations
        
        elif attack_type == AttackType.CLUSTER_BOMB:
            # All combinations (Cartesian product)
            import itertools
            
            if not positions:
                return []
            
            payload_lists = [
                [(pos.position_id, payload) 
                 for payload in payload_sets.get(pos.position_id, [])]
                for pos in positions
            ]
            
            combinations = []
            for combo in itertools.product(*payload_lists):
                combinations.append(dict(combo))
            
            return combinations
        
        return []
    
    def get_results(self, session_id: str) -> List[Dict[str, Any]]:
        """Get attack results"""
        session = self.sessions.get(session_id)
        if not session:
            return []
        
        return [
            {
                'request_num': result.request_num,
                'payloads': result.payloads,
                'status_code': result.get_status_code(),
                'content_length': result.get_content_length(),
                'duration_ms': result.get_duration(),
                'extracted_data': result.extracted_data
            }
            for result in session['results']
        ]
    
    def analyze_results(self, session_id: str) -> Dict[str, Any]:
        """Analyze attack results"""
        session = self.sessions.get(session_id)
        if not session:
            return {}
        
        results = session['results']
        
        if not results:
            return {'error': 'No results'}
        
        # Status code distribution
        status_codes = {}
        for result in results:
            code = result.get_status_code()
            status_codes[code] = status_codes.get(code, 0) + 1
        
        # Content length statistics
        lengths = [result.get_content_length() for result in results]
        
        # Duration statistics
        durations = [result.get_duration() for result in results]
        
        analysis = {
            'total_requests': len(results),
            'status_codes': status_codes,
            'content_length': {
                'min': min(lengths) if lengths else 0,
                'max': max(lengths) if lengths else 0,
                'avg': sum(lengths) / len(lengths) if lengths else 0
            },
            'duration_ms': {
                'min': min(durations) if durations else 0,
                'max': max(durations) if durations else 0,
                'avg': sum(durations) / len(durations) if durations else 0
            },
            'unique_responses': len(set(
                result.get_content_length() for result in results
            ))
        }
        
        return analysis
    
    def stop_attack(self, session_id: str) -> bool:
        """Stop running attack"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        if session['status'] == 'running':
            session['status'] = 'stopped'
            logger.info(f"Stopped attack: {session_id}")
            return True
        
        return False


# Global intruder instance
intruder = HTTPIntruder()


# Convenience functions
def create_intruder_attack(request: Dict[str, Any], attack_type: str = 'sniper') -> str:
    """Create intruder attack session"""
    attack_enum = AttackType(attack_type)
    return intruder.create_session(request, attack_enum)


async def run_intruder_attack(session_id: str, max_concurrent: int = 10) -> bool:
    """Run intruder attack"""
    return await intruder.start_attack(session_id, max_concurrent)


# Export
__all__ = [
    'HTTPIntruder',
    'AttackType',
    'IntruderRequest',
    'IntruderResult',
    'intruder',
    'create_intruder_attack',
    'run_intruder_attack'
]

