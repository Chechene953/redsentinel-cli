"""
State Machine - Manages application and scan state transitions
Ensures valid state transitions and tracks current state
"""

from enum import Enum
from typing import Dict, List, Callable, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ScanState(Enum):
    """Scan lifecycle states"""
    INITIALIZED = "initialized"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AppState(Enum):
    """Application states"""
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"
    SHUTTING_DOWN = "shutting_down"


class StateTransitionError(Exception):
    """Raised when invalid state transition is attempted"""
    pass


class StateMachine:
    """
    State machine for managing state transitions
    
    Features:
    - Valid transition enforcement
    - State history tracking
    - Transition callbacks
    - Current state persistence
    """
    
    # Valid state transitions for scans
    SCAN_TRANSITIONS = {
        ScanState.INITIALIZED: [ScanState.RECONNAISSANCE, ScanState.SCANNING, ScanState.CANCELLED],
        ScanState.RECONNAISSANCE: [ScanState.SCANNING, ScanState.CANCELLED, ScanState.FAILED],
        ScanState.SCANNING: [ScanState.EXPLOITATION, ScanState.REPORTING, ScanState.COMPLETED, ScanState.CANCELLED, ScanState.FAILED],
        ScanState.EXPLOITATION: [ScanState.POST_EXPLOITATION, ScanState.REPORTING, ScanState.CANCELLED, ScanState.FAILED],
        ScanState.POST_EXPLOITATION: [ScanState.REPORTING, ScanState.CANCELLED, ScanState.FAILED],
        ScanState.REPORTING: [ScanState.COMPLETED, ScanState.FAILED],
        ScanState.COMPLETED: [],
        ScanState.FAILED: [],
        ScanState.CANCELLED: []
    }
    
    # Valid state transitions for app
    APP_TRANSITIONS = {
        AppState.INITIALIZING: [AppState.READY, AppState.ERROR],
        AppState.READY: [AppState.BUSY, AppState.SHUTTING_DOWN, AppState.ERROR],
        AppState.BUSY: [AppState.READY, AppState.ERROR],
        AppState.ERROR: [AppState.READY, AppState.SHUTTING_DOWN],
        AppState.SHUTTING_DOWN: []
    }
    
    def __init__(self, initial_state: Enum):
        self.current_state = initial_state
        self.state_history: List[Dict[str, Any]] = []
        self._callbacks: Dict[Enum, List[Callable]] = {}
        
        # Record initial state
        self._record_state(initial_state)
    
    def _record_state(self, state: Enum, metadata: Dict = None):
        """Record state in history"""
        self.state_history.append({
            'state': state,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {}
        })
    
    def _get_valid_transitions(self, state: Enum) -> List[Enum]:
        """Get valid transitions for a state"""
        if isinstance(state, ScanState):
            return self.SCAN_TRANSITIONS.get(state, [])
        elif isinstance(state, AppState):
            return self.APP_TRANSITIONS.get(state, [])
        return []
    
    def transition(self, new_state: Enum, metadata: Dict = None) -> bool:
        """
        Transition to a new state
        
        Args:
            new_state: Target state
            metadata: Additional data about the transition
            
        Returns:
            True if transition successful
            
        Raises:
            StateTransitionError: If transition is invalid
        """
        valid_transitions = self._get_valid_transitions(self.current_state)
        
        if new_state not in valid_transitions:
            raise StateTransitionError(
                f"Invalid transition from {self.current_state.value} to {new_state.value}"
            )
        
        # Execute callbacks
        self._execute_callbacks(new_state, metadata)
        
        # Record transition
        logger.info(f"State transition: {self.current_state.value} -> {new_state.value}")
        
        self.current_state = new_state
        self._record_state(new_state, metadata)
        
        return True
    
    def can_transition(self, new_state: Enum) -> bool:
        """Check if transition is valid"""
        valid_transitions = self._get_valid_transitions(self.current_state)
        return new_state in valid_transitions
    
    def register_callback(self, state: Enum, callback: Callable):
        """Register a callback for state entry"""
        if state not in self._callbacks:
            self._callbacks[state] = []
        
        self._callbacks[state].append(callback)
    
    def _execute_callbacks(self, state: Enum, metadata: Dict = None):
        """Execute callbacks for state entry"""
        if state in self._callbacks:
            for callback in self._callbacks[state]:
                try:
                    callback(metadata)
                except Exception as e:
                    logger.error(f"Error in state callback: {e}")
    
    def get_state_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get state history"""
        return self.state_history[-limit:]
    
    def get_current_state(self) -> Enum:
        """Get current state"""
        return self.current_state
    
    def is_terminal_state(self) -> bool:
        """Check if current state is terminal (no valid transitions)"""
        valid_transitions = self._get_valid_transitions(self.current_state)
        return len(valid_transitions) == 0
    
    def reset(self, initial_state: Enum):
        """Reset state machine"""
        self.current_state = initial_state
        self.state_history.clear()
        self._record_state(initial_state)
        logger.info(f"State machine reset to {initial_state.value}")


class ScanStateMachine(StateMachine):
    """State machine specifically for scan lifecycle"""
    
    def __init__(self, scan_id: str):
        super().__init__(ScanState.INITIALIZED)
        self.scan_id = scan_id
        
        # Register default callbacks
        self.register_callback(ScanState.COMPLETED, self._on_completed)
        self.register_callback(ScanState.FAILED, self._on_failed)
    
    def _on_completed(self, metadata: Dict = None):
        """Called when scan completes"""
        logger.info(f"Scan {self.scan_id} completed successfully")
    
    def _on_failed(self, metadata: Dict = None):
        """Called when scan fails"""
        error = metadata.get('error', 'Unknown error') if metadata else 'Unknown error'
        logger.error(f"Scan {self.scan_id} failed: {error}")
    
    def start_recon(self):
        """Start reconnaissance phase"""
        return self.transition(ScanState.RECONNAISSANCE)
    
    def start_scanning(self):
        """Start scanning phase"""
        return self.transition(ScanState.SCANNING)
    
    def start_exploitation(self):
        """Start exploitation phase"""
        return self.transition(ScanState.EXPLOITATION)
    
    def start_reporting(self):
        """Start reporting phase"""
        return self.transition(ScanState.REPORTING)
    
    def complete(self):
        """Mark scan as completed"""
        return self.transition(ScanState.COMPLETED)
    
    def fail(self, error: str = None):
        """Mark scan as failed"""
        return self.transition(ScanState.FAILED, {'error': error})
    
    def cancel(self):
        """Cancel scan"""
        return self.transition(ScanState.CANCELLED)


class AppStateMachine(StateMachine):
    """State machine for application lifecycle"""
    
    def __init__(self):
        super().__init__(AppState.INITIALIZING)
    
    def mark_ready(self):
        """Mark application as ready"""
        return self.transition(AppState.READY)
    
    def mark_busy(self):
        """Mark application as busy"""
        return self.transition(AppState.BUSY)
    
    def mark_error(self, error: str = None):
        """Mark application as in error state"""
        return self.transition(AppState.ERROR, {'error': error})
    
    def start_shutdown(self):
        """Start application shutdown"""
        return self.transition(AppState.SHUTTING_DOWN)


# Example usage
if __name__ == "__main__":
    # Example: Scan state machine
    scan_sm = ScanStateMachine("scan-001")
    
    print(f"Initial state: {scan_sm.get_current_state()}")
    
    scan_sm.start_recon()
    print(f"After recon: {scan_sm.get_current_state()}")
    
    scan_sm.start_scanning()
    print(f"After scanning: {scan_sm.get_current_state()}")
    
    scan_sm.start_reporting()
    print(f"After reporting: {scan_sm.get_current_state()}")
    
    scan_sm.complete()
    print(f"Final state: {scan_sm.get_current_state()}")
    
    print(f"Is terminal: {scan_sm.is_terminal_state()}")
