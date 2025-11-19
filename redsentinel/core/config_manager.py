"""
Configuration Manager - Centralized configuration management
Handles loading, saving, and accessing configuration
"""

import os
import yaml
import json
from pathlib import Path
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Centralized configuration management
    
    Features:
    - YAML/JSON configuration files
    - Environment variable overrides
    - Default values
    - Configuration validation
    - Hot-reload capability
    """
    
    DEFAULT_CONFIG = {
        'general': {
            'app_name': 'RedSentinel',
            'version': '7.0.0',
            'log_level': 'INFO',
            'max_threads': 10,
            'timeout': 30
        },
        'database': {
            'type': 'sqlite',
            'sqlite_path': './data/redsentinel.db',
            'postgres_host': 'localhost',
            'postgres_port': 5432,
            'postgres_db': 'redsentinel',
            'postgres_user': 'redsentinel',
            'postgres_password': ''
        },
        'scanning': {
            'max_concurrent_scans': 5,
            'default_timeout': 30,
            'rate_limit': 100,
            'user_agent': 'RedSentinel/6.0',
            'follow_redirects': True,
            'verify_ssl': True
        },
        'recon': {
            'subdomain_wordlist': '/usr/share/wordlists/subdomains.txt',
            'port_scan_timeout': 5,
            'max_subdomain_depth': 3,
            'enable_dns_bruteforce': True
        },
        'osint': {
            'shodan_api_key': '',
            'virustotal_api_key': '',
            'censys_api_id': '',
            'censys_api_secret': '',
            'github_token': '',
            'haveibeenpwned_api_key': ''
        },
        'reporting': {
            'output_dir': './reports',
            'default_format': 'html',
            'include_screenshots': False,
            'compliance_frameworks': ['OWASP', 'PCI-DSS']
        },
        'api_server': {
            'enabled': False,
            'host': '127.0.0.1',
            'port': 8000,
            'cors_enabled': True,
            'jwt_secret': 'change-me-in-production'
        },
        'performance': {
            'enable_caching': True,
            'cache_ttl': 3600,
            'connection_pool_size': 20,
            'redis_host': 'localhost',
            'redis_port': 6379
        }
    }
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = Path(config_file)
        self.config: Dict[str, Any] = self.DEFAULT_CONFIG.copy()
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    if self.config_file.suffix == '.yaml' or self.config_file.suffix == '.yml':
                        user_config = yaml.safe_load(f)
                    elif self.config_file.suffix == '.json':
                        user_config = json.load(f)
                    else:
                        logger.error(f"Unsupported config file format: {self.config_file.suffix}")
                        return
                
                # Merge user config with defaults
                self._deep_merge(self.config, user_config)
                logger.info(f"Loaded configuration from {self.config_file}")
            
            except Exception as e:
                logger.error(f"Error loading config file: {e}")
        else:
            logger.warning(f"Config file not found: {self.config_file}. Using defaults.")
            self.save_config()
    
    def _deep_merge(self, base: Dict, updates: Dict):
        """Recursively merge dictionaries"""
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Example:
            config.get('database.type')
            config.get('scanning.max_concurrent_scans')
        """
        # Check environment variable first (uppercase with underscores)
        env_key = f"REDSENTINEL_{key.upper().replace('.', '_')}"
        env_value = os.getenv(env_key)
        
        if env_value is not None:
            return env_value
        
        # Navigate through nested config
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        
        Example:
            config.set('database.type', 'postgres')
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
        logger.debug(f"Set config: {key} = {value}")
    
    def save_config(self, file_path: Optional[str] = None):
        """Save configuration to file"""
        target_file = Path(file_path) if file_path else self.config_file
        
        try:
            # Create directory if needed
            target_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(target_file, 'w') as f:
                if target_file.suffix == '.yaml' or target_file.suffix == '.yml':
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                elif target_file.suffix == '.json':
                    json.dump(self.config, f, indent=2)
            
            logger.info(f"Saved configuration to {target_file}")
            return True
        
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def reload(self):
        """Reload configuration from file"""
        logger.info("Reloading configuration...")
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_config()
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.config.get(section, {})
    
    def update_section(self, section: str, values: Dict[str, Any]):
        """Update entire configuration section"""
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section].update(values)
        logger.debug(f"Updated config section: {section}")
    
    def validate(self) -> bool:
        """Validate configuration"""
        # Basic validation
        required_sections = ['general', 'database', 'scanning']
        
        for section in required_sections:
            if section not in self.config:
                logger.error(f"Missing required config section: {section}")
                return False
        
        logger.info("Configuration validation passed")
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Get full configuration as dictionary"""
        return self.config.copy()


# Global configuration instance
config = ConfigManager()


# Convenience functions
def get_config(key: str, default: Any = None) -> Any:
    """Get configuration value"""
    return config.get(key, default)


def set_config(key: str, value: Any):
    """Set configuration value"""
    config.set(key, value)


def reload_config():
    """Reload configuration"""
    config.reload()
