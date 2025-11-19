"""
HTTP Repeater
Like Burp Suite Repeater - Manually modify and replay HTTP requests

Features:
- Manual request modification
- Request replay
- Response comparison
- History tracking
- Request templates
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import copy

logger = logging.getLogger(__name__)


class RepeaterSession:
    """Individual repeater session"""
    
    def __init__(self, session_id: str, original_request: Dict[str, Any]):
        self.session_id = session_id
        self.original_request = original_request
        self.modified_request = copy.deepcopy(original_request)
        self.responses: List[Dict[str, Any]] = []
        self.created_at = datetime.utcnow()
        self.last_sent_at: Optional[datetime] = None
    
    def modify_request(self, modifications: Dict[str, Any]):
        """Apply modifications to request"""
        for key, value in modifications.items():
            if key == 'headers':
                self.modified_request['headers'].update(value)
            elif key == 'body':
                self.modified_request['body'] = value
            elif key == 'method':
                self.modified_request['method'] = value.upper()
            elif key == 'path':
                self.modified_request['path'] = value
            elif key == 'params':
                self.modified_request['params'] = value
            else:
                self.modified_request[key] = value
    
    def reset_modifications(self):
        """Reset to original request"""
        self.modified_request = copy.deepcopy(self.original_request)
    
    def add_response(self, response: Dict[str, Any]):
        """Add response to history"""
        self.responses.append({
            'timestamp': datetime.utcnow().isoformat(),
            'response': response
        })
        self.last_sent_at = datetime.utcnow()
    
    def get_latest_response(self) -> Optional[Dict[str, Any]]:
        """Get most recent response"""
        return self.responses[-1] if self.responses else None
    
    def compare_responses(self, index1: int, index2: int) -> Dict[str, Any]:
        """Compare two responses"""
        if index1 >= len(self.responses) or index2 >= len(self.responses):
            return {'error': 'Invalid response indices'}
        
        resp1 = self.responses[index1]['response']
        resp2 = self.responses[index2]['response']
        
        comparison = {
            'status_code': {
                'response1': resp1.get('status_code'),
                'response2': resp2.get('status_code'),
                'different': resp1.get('status_code') != resp2.get('status_code')
            },
            'content_length': {
                'response1': len(resp1.get('content', '')),
                'response2': len(resp2.get('content', '')),
                'different': len(resp1.get('content', '')) != len(resp2.get('content', ''))
            },
            'headers_diff': self._diff_headers(
                resp1.get('headers', {}),
                resp2.get('headers', {})
            )
        }
        
        return comparison
    
    def _diff_headers(self, headers1: Dict, headers2: Dict) -> Dict[str, Any]:
        """Find differences in headers"""
        all_keys = set(headers1.keys()) | set(headers2.keys())
        
        diff = {
            'only_in_response1': [],
            'only_in_response2': [],
            'different_values': []
        }
        
        for key in all_keys:
            if key not in headers2:
                diff['only_in_response1'].append(key)
            elif key not in headers1:
                diff['only_in_response2'].append(key)
            elif headers1[key] != headers2[key]:
                diff['different_values'].append({
                    'header': key,
                    'value1': headers1[key],
                    'value2': headers2[key]
                })
        
        return diff


class HTTPRepeater:
    """
    HTTP Request Repeater
    Manually modify and replay requests like Burp Repeater
    """
    
    def __init__(self):
        self.sessions: Dict[str, RepeaterSession] = {}
        self._session_counter = 0
    
    def create_session(self, request: Dict[str, Any]) -> str:
        """
        Create new repeater session
        
        Args:
            request: Original request data
        
        Returns:
            Session ID
        """
        session_id = f"repeater_{self._session_counter}"
        self._session_counter += 1
        
        session = RepeaterSession(session_id, request)
        self.sessions[session_id] = session
        
        logger.info(f"Created repeater session: {session_id}")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[RepeaterSession]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def modify_request(self, session_id: str, modifications: Dict[str, Any]) -> bool:
        """
        Modify request in session
        
        Args:
            session_id: Session ID
            modifications: Modifications to apply
        
        Returns:
            Success status
        """
        session = self.sessions.get(session_id)
        if not session:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session.modify_request(modifications)
        logger.info(f"Modified request in session: {session_id}")
        return True
    
    async def send_request(self, session_id: str, follow_redirects: bool = False) -> Optional[Dict[str, Any]]:
        """
        Send modified request
        
        Args:
            session_id: Session ID
            follow_redirects: Whether to follow redirects
        
        Returns:
            Response data or None
        """
        session = self.sessions.get(session_id)
        if not session:
            logger.error(f"Session not found: {session_id}")
            return None
        
        request = session.modified_request
        
        try:
            # Build URL
            scheme = request.get('scheme', 'https')
            host = request.get('host', '')
            port = request.get('port', 443 if scheme == 'https' else 80)
            path = request.get('path', '/')
            
            if port in (80, 443):
                url = f"{scheme}://{host}{path}"
            else:
                url = f"{scheme}://{host}:{port}{path}"
            
            # Prepare request
            method = request.get('method', 'GET')
            headers = request.get('headers', {})
            body = request.get('body', '')
            params = request.get('params', {})
            
            logger.info(f"Sending {method} {url}")
            
            start_time = datetime.utcnow()
            
            # Send request
            async with aiohttp.ClientSession() as http_session:
                async with http_session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body if body else None,
                    params=params,
                    allow_redirects=follow_redirects,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    end_time = datetime.utcnow()
                    duration_ms = (end_time - start_time).total_seconds() * 1000
                    
                    # Read response
                    content = await response.text()
                    
                    response_data = {
                        'status_code': response.status,
                        'reason': response.reason,
                        'headers': dict(response.headers),
                        'content': content,
                        'duration_ms': duration_ms,
                        'url': str(response.url)
                    }
                    
                    # Add to session history
                    session.add_response(response_data)
                    
                    logger.info(f"Response received: {response.status} ({duration_ms:.0f}ms)")
                    
                    return response_data
        
        except Exception as e:
            logger.error(f"Error sending request: {e}")
            
            error_response = {
                'error': str(e),
                'status_code': 0,
                'content': '',
                'duration_ms': 0
            }
            
            session.add_response(error_response)
            return error_response
    
    async def send_multiple(self, session_id: str, count: int = 10, 
                           delay_ms: int = 0) -> List[Dict[str, Any]]:
        """
        Send request multiple times
        
        Args:
            session_id: Session ID
            count: Number of times to send
            delay_ms: Delay between requests in milliseconds
        
        Returns:
            List of responses
        """
        responses = []
        
        for i in range(count):
            logger.info(f"Sending request {i+1}/{count}")
            
            response = await self.send_request(session_id)
            if response:
                responses.append(response)
            
            if delay_ms > 0 and i < count - 1:
                await asyncio.sleep(delay_ms / 1000.0)
        
        logger.info(f"Completed {len(responses)} requests")
        return responses
    
    def get_response_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Get response history for session"""
        session = self.sessions.get(session_id)
        if not session:
            return []
        
        return session.responses
    
    def compare_responses(self, session_id: str, index1: int, index2: int) -> Dict[str, Any]:
        """Compare two responses in session"""
        session = self.sessions.get(session_id)
        if not session:
            return {'error': 'Session not found'}
        
        return session.compare_responses(index1, index2)
    
    def reset_session(self, session_id: str) -> bool:
        """Reset session to original request"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        session.reset_modifications()
        logger.info(f"Reset session: {session_id}")
        return True
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            logger.info(f"Deleted session: {session_id}")
            return True
        return False
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all sessions"""
        return [
            {
                'session_id': session.session_id,
                'method': session.modified_request.get('method'),
                'url': session.modified_request.get('url'),
                'created_at': session.created_at.isoformat(),
                'last_sent_at': session.last_sent_at.isoformat() if session.last_sent_at else None,
                'response_count': len(session.responses)
            }
            for session in self.sessions.values()
        ]
    
    def export_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Export session data"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            'session_id': session.session_id,
            'original_request': session.original_request,
            'modified_request': session.modified_request,
            'responses': session.responses,
            'created_at': session.created_at.isoformat()
        }
    
    def save_as_template(self, session_id: str, template_name: str) -> bool:
        """Save modified request as template"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        # This could be saved to file or database
        # Simplified version for now
        logger.info(f"Saved template: {template_name}")
        return True


# Global repeater instance
repeater = HTTPRepeater()


# Convenience functions
def repeat_request(request: Dict[str, Any]) -> str:
    """
    Create repeater session from request
    
    Args:
        request: Request data
    
    Returns:
        Session ID
    """
    return repeater.create_session(request)


async def send_modified_request(session_id: str, 
                                modifications: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Modify and send request
    
    Args:
        session_id: Session ID
        modifications: Optional modifications
    
    Returns:
        Response data
    """
    if modifications:
        repeater.modify_request(session_id, modifications)
    
    return await repeater.send_request(session_id)


# Export
__all__ = ['HTTPRepeater', 'RepeaterSession', 'repeater', 'repeat_request', 'send_modified_request']

