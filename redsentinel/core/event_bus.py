"""
Event Bus - Asynchronous event-driven architecture
Allows modules to communicate without tight coupling
"""

import asyncio
from typing import Callable, Dict, List, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EventBus:
    """
    Central event bus for publish-subscribe pattern
    
    Features:
    - Asynchronous event handling
    - Multiple subscribers per event
    - Event history
    - Priority-based execution
    """
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._event_history: List[Dict[str, Any]] = []
        self._max_history = 1000
        
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to an event type"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        
        self._subscribers[event_type].append(callback)
        logger.debug(f"Subscribed to event: {event_type}")
        
    def unsubscribe(self, event_type: str, callback: Callable):
        """Unsubscribe from an event type"""
        if event_type in self._subscribers:
            self._subscribers[event_type].remove(callback)
            logger.debug(f"Unsubscribed from event: {event_type}")
    
    async def publish(self, event_type: str, data: Any = None):
        """
        Publish an event to all subscribers
        
        Args:
            event_type: Type of event (e.g., 'scan.started', 'vuln.found')
            data: Event data payload
        """
        event = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add to history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)
        
        # Notify subscribers
        if event_type in self._subscribers:
            tasks = []
            for callback in self._subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        tasks.append(callback(data))
                    else:
                        callback(data)
                except Exception as e:
                    logger.error(f"Error in event handler for {event_type}: {e}")
            
            # Wait for all async tasks
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.debug(f"Published event: {event_type}")
    
    def get_history(self, event_type: str = None, limit: int = 100) -> List[Dict]:
        """Get event history"""
        if event_type:
            history = [e for e in self._event_history if e['type'] == event_type]
        else:
            history = self._event_history
        
        return history[-limit:]
    
    def clear_history(self):
        """Clear event history"""
        self._event_history.clear()
    
    def get_subscriber_count(self, event_type: str = None) -> int:
        """Get number of subscribers"""
        if event_type:
            return len(self._subscribers.get(event_type, []))
        else:
            return sum(len(subs) for subs in self._subscribers.values())


# Global event bus instance
event_bus = EventBus()


# Common event types
class EventTypes:
    """Standard event type constants"""
    
    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_PROGRESS = "scan.progress"
    
    # Vulnerability events
    VULN_FOUND = "vulnerability.found"
    VULN_CONFIRMED = "vulnerability.confirmed"
    VULN_FALSE_POSITIVE = "vulnerability.false_positive"
    
    # Target events
    TARGET_ADDED = "target.added"
    TARGET_UPDATED = "target.updated"
    TARGET_REMOVED = "target.removed"
    
    # Recon events
    RECON_SUBDOMAIN_FOUND = "recon.subdomain_found"
    RECON_PORT_OPEN = "recon.port_open"
    RECON_SERVICE_DETECTED = "recon.service_detected"
    
    # OSINT events
    OSINT_EMAIL_FOUND = "osint.email_found"
    OSINT_LEAK_FOUND = "osint.leak_found"
    OSINT_CREDENTIAL_FOUND = "osint.credential_found"
    
    # Exploit events
    EXPLOIT_SUCCESS = "exploit.success"
    EXPLOIT_FAILED = "exploit.failed"
    
    # System events
    SYSTEM_ERROR = "system.error"
    SYSTEM_WARNING = "system.warning"
    SYSTEM_INFO = "system.info"


# Example usage and decorators
def on_event(event_type: str):
    """Decorator to register a function as an event handler"""
    def decorator(func: Callable):
        event_bus.subscribe(event_type, func)
        return func
    return decorator


# Example event handlers (for demonstration)
@on_event(EventTypes.VULN_FOUND)
async def log_vulnerability(data):
    """Log when vulnerability is found"""
    logger.info(f"Vulnerability found: {data.get('name', 'Unknown')}")


@on_event(EventTypes.SCAN_COMPLETED)
async def scan_complete_handler(data):
    """Handle scan completion"""
    logger.info(f"Scan completed for target: {data.get('target', 'Unknown')}")
