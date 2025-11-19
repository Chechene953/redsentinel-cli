"""
Professional Logging Configuration
Features:
- Rotating file handlers
- Colored console output
- Structured logging
- Multiple log levels
- Audit trail support
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime
import json

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    COLORS = {
        'DEBUG': Fore.CYAN if COLORAMA_AVAILABLE else '',
        'INFO': Fore.GREEN if COLORAMA_AVAILABLE else '',
        'WARNING': Fore.YELLOW if COLORAMA_AVAILABLE else '',
        'ERROR': Fore.RED if COLORAMA_AVAILABLE else '',
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT if COLORAMA_AVAILABLE else '',
    }
    
    RESET = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
    
    def format(self, record):
        # Add color to levelname
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        
        # Format the message
        result = super().format(record)
        
        # Reset levelname for other handlers
        record.levelname = levelname
        
        return result


class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data)


class AuditLogger:
    """Separate audit logger for security-relevant events"""
    
    def __init__(self, log_dir: str = "./logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        
        # Audit log file (never rotated, append only)
        audit_file = self.log_dir / 'audit.log'
        file_handler = logging.FileHandler(audit_file, mode='a')
        file_handler.setLevel(logging.INFO)
        
        # Use JSON format for audit logs
        json_formatter = JsonFormatter()
        file_handler.setFormatter(json_formatter)
        
        self.logger.addHandler(file_handler)
    
    def log_action(self, action: str, target: str = None, user: str = None, 
                   details: dict = None, success: bool = True):
        """Log an audit event"""
        extra_fields = {
            'action': action,
            'target': target,
            'user': user or 'system',
            'success': success,
            'details': details or {}
        }
        
        # Create a log record with extra fields
        record = self.logger.makeRecord(
            self.logger.name, logging.INFO, '', 0, 
            f"Action: {action}, Target: {target}, Success: {success}",
            (), None
        )
        record.extra_fields = extra_fields
        
        self.logger.handle(record)


def setup_logging(
    log_level: str = "INFO",
    log_dir: str = "./logs",
    log_file: str = "redsentinel.log",
    max_bytes: int = 100 * 1024 * 1024,  # 100MB
    backup_count: int = 10,
    console_output: bool = True,
    json_logging: bool = False,
    audit_enabled: bool = True
) -> logging.Logger:
    """
    Setup comprehensive logging configuration
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        log_file: Main log file name
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        console_output: Enable console output
        json_logging: Use JSON format for file logs
        audit_enabled: Enable audit logging
    
    Returns:
        Configured logger instance
    """
    
    # Create log directory
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    # Get root logger
    logger = logging.getLogger('redsentinel')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console Handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        console_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
        console_formatter = ColoredFormatter(
            console_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # Rotating File Handler (Main Log)
    file_handler = logging.handlers.RotatingFileHandler(
        log_path / log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    
    if json_logging:
        file_formatter = JsonFormatter()
    else:
        file_format = '%(asctime)s - %(levelname)s - %(name)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s'
        file_formatter = logging.Formatter(file_format, datefmt='%Y-%m-%d %H:%M:%S')
    
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Error File Handler (Separate file for errors)
    error_handler = logging.handlers.RotatingFileHandler(
        log_path / 'errors.log',
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(pathname)s:%(lineno)d\n'
        '%(message)s\n'
        '%(exc_info)s\n',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    error_handler.setFormatter(error_formatter)
    logger.addHandler(error_handler)
    
    # Debug File Handler (Only in DEBUG mode)
    if log_level.upper() == 'DEBUG':
        debug_handler = logging.handlers.RotatingFileHandler(
            log_path / 'debug.log',
            maxBytes=max_bytes,
            backupCount=5,
            encoding='utf-8'
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(process)d:%(thread)d] - %(name)s - %(pathname)s:%(lineno)d\n'
            '%(message)s\n',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        debug_handler.setFormatter(debug_formatter)
        logger.addHandler(debug_handler)
    
    # Setup audit logger
    if audit_enabled:
        audit_logger = AuditLogger(log_dir)
        # Store audit logger reference
        logger.audit = audit_logger.log_action
    
    logger.info(f"Logging initialized - Level: {log_level}, Output: {log_dir}")
    
    return logger


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance
    
    Args:
        name: Logger name (usually __name__ of the module)
    
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f'redsentinel.{name}')
    return logging.getLogger('redsentinel')


class ContextLogger:
    """Context manager for logging with additional context"""
    
    def __init__(self, logger: logging.Logger, **context):
        self.logger = logger
        self.context = context
        self.old_factory = None
    
    def __enter__(self):
        # Store old factory
        self.old_factory = logging.getLogRecordFactory()
        
        # Create new factory with context
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore old factory
        logging.setLogRecordFactory(self.old_factory)


# Performance logging decorator
def log_performance(logger: Optional[logging.Logger] = None):
    """Decorator to log function execution time"""
    import time
    import functools
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time
                logger.debug(f"{func.__name__} executed in {elapsed:.4f}s")
                return result
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"{func.__name__} failed after {elapsed:.4f}s: {e}")
                raise
        
        return wrapper
    return decorator


# Exception logging decorator
def log_exceptions(logger: Optional[logging.Logger] = None):
    """Decorator to automatically log exceptions"""
    import functools
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.exception(f"Exception in {func.__name__}: {e}")
                raise
        
        return wrapper
    return decorator


# Module-level initialization
_global_logger = None


def init_logging_from_config(config_manager=None):
    """Initialize logging from configuration"""
    global _global_logger
    
    if config_manager:
        log_level = config_manager.get('general.log_level', 'INFO')
        log_dir = config_manager.get('general.log_dir', './logs')
        max_log_size = config_manager.get('general.max_log_size_mb', 100) * 1024 * 1024
        audit_enabled = config_manager.get('general.audit_trail', True)
    else:
        log_level = 'INFO'
        log_dir = './logs'
        max_log_size = 100 * 1024 * 1024
        audit_enabled = True
    
    _global_logger = setup_logging(
        log_level=log_level,
        log_dir=log_dir,
        max_bytes=max_log_size,
        audit_enabled=audit_enabled
    )
    
    return _global_logger


# Convenience function
def get_global_logger() -> logging.Logger:
    """Get the global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = setup_logging()
    return _global_logger


# Export commonly used functions
__all__ = [
    'setup_logging',
    'get_logger',
    'get_global_logger',
    'init_logging_from_config',
    'ContextLogger',
    'AuditLogger',
    'log_performance',
    'log_exceptions',
    'ColoredFormatter',
    'JsonFormatter'
]

