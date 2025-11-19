"""
Error Handler - Centralized error handling and logging
Provides consistent error handling across the application
"""

import logging
import traceback
from typing import Optional, Callable, Any
from functools import wraps
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorContext:
    """Context information for errors"""
    
    def __init__(self, 
                 operation: str,
                 target: Optional[str] = None,
                 details: Optional[dict] = None):
        self.operation = operation
        self.target = target
        self.details = details or {}
    
    def to_dict(self):
        return {
            'operation': self.operation,
            'target': self.target,
            'details': self.details
        }


class ErrorHandler:
    """
    Centralized error handler
    
    Features:
    - Error logging
    - Context tracking
    - Error categorization
    - Recovery suggestions
    """
    
    def __init__(self):
        self.error_count = 0
        self.errors = []
    
    def handle_error(self, 
                    error: Exception, 
                    context: Optional[ErrorContext] = None,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM):
        """
        Handle an error with context
        
        Args:
            error: The exception
            context: Error context
            severity: Error severity
        """
        self.error_count += 1
        
        error_info = {
            'error': str(error),
            'type': type(error).__name__,
            'severity': severity.value,
            'context': context.to_dict() if context else None,
            'traceback': traceback.format_exc()
        }
        
        self.errors.append(error_info)
        
        # Log based on severity
        if severity in (ErrorSeverity.CRITICAL, ErrorSeverity.HIGH):
            logger.error(f"Error in {context.operation if context else 'unknown'}: {error}", exc_info=True)
        else:
            logger.warning(f"Error in {context.operation if context else 'unknown'}: {error}")
        
        return error_info
    
    def get_errors(self):
        """Get all errors"""
        return self.errors
    
    def clear_errors(self):
        """Clear error history"""
        self.errors.clear()
        self.error_count = 0


# Global error handler
_error_handler = ErrorHandler()


def get_error_handler() -> ErrorHandler:
    """Get global error handler instance"""
    return _error_handler


def handle_errors(operation: str = None, severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """
    Decorator to handle errors in functions
    
    Usage:
        @handle_errors(operation="port_scan")
        def scan_port(host, port):
            ...
    """
    def decorator(func: Callable) -> Callable:
        op_name = operation or func.__name__
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                context = ErrorContext(
                    operation=op_name,
                    details={'args': str(args), 'kwargs': str(kwargs)}
                )
                _error_handler.handle_error(e, context, severity)
                raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                context = ErrorContext(
                    operation=op_name,
                    details={'args': str(args), 'kwargs': str(kwargs)}
                )
                _error_handler.handle_error(e, context, severity)
                raise
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Convenience functions
def log_error(error: Exception, operation: str, target: str = None):
    """Log an error with context"""
    context = ErrorContext(operation=operation, target=target)
    _error_handler.handle_error(error, context)


def get_last_error():
    """Get last error"""
    errors = _error_handler.get_errors()
    return errors[-1] if errors else None


# Example usage
if __name__ == "__main__":
    @handle_errors(operation="test_function")
    def test_function(x):
        if x < 0:
            raise ValueError("Negative value not allowed")
        return x * 2
    
    try:
        result = test_function(-1)
    except ValueError:
        print("Error caught and logged")
    
    print(f"Total errors: {get_error_handler().error_count}")

