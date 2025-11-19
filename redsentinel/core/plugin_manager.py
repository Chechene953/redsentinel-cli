"""
Plugin Manager - Dynamic plugin loading and management
Enables extensibility without modifying core code
"""

import importlib
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Any, Type
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class PluginBase(ABC):
    """Base class for all plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    def description(self) -> str:
        """Plugin description"""
        return ""
    
    @abstractmethod
    async def initialize(self):
        """Initialize plugin"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Cleanup plugin resources"""
        pass


class ScannerPlugin(PluginBase):
    """Base class for scanner plugins"""
    
    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan"""
        pass


class ReportPlugin(PluginBase):
    """Base class for report plugins"""
    
    @abstractmethod
    async def generate_report(self, data: Dict[str, Any]) -> str:
        """Generate report"""
        pass


class ExploitPlugin(PluginBase):
    """Base class for exploit plugins"""
    
    @abstractmethod
    async def exploit(self, target: str, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Execute exploit"""
        pass


class PluginManager:
    """
    Manages plugin lifecycle
    
    Features:
    - Dynamic plugin loading
    - Hot-reload capability
    - Dependency management
    - Plugin isolation
    """
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self._plugins: Dict[str, PluginBase] = {}
        self._plugin_classes: Dict[str, Type[PluginBase]] = {}
        
    def discover_plugins(self) -> List[str]:
        """Discover available plugins in plugin directory"""
        if not self.plugin_dir.exists():
            logger.warning(f"Plugin directory not found: {self.plugin_dir}")
            return []
        
        discovered = []
        
        for file_path in self.plugin_dir.glob("*.py"):
            if file_path.name.startswith("_"):
                continue
            
            try:
                # Load module
                module_name = f"plugins.{file_path.stem}"
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Find plugin classes
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, PluginBase) and obj != PluginBase:
                            plugin_name = file_path.stem
                            self._plugin_classes[plugin_name] = obj
                            discovered.append(plugin_name)
                            logger.info(f"Discovered plugin: {plugin_name}")
            
            except Exception as e:
                logger.error(f"Error discovering plugin {file_path}: {e}")
        
        return discovered
    
    async def load_plugin(self, plugin_name: str) -> bool:
        """Load and initialize a plugin"""
        if plugin_name in self._plugins:
            logger.warning(f"Plugin already loaded: {plugin_name}")
            return True
        
        if plugin_name not in self._plugin_classes:
            logger.error(f"Plugin not found: {plugin_name}")
            return False
        
        try:
            # Instantiate plugin
            plugin_class = self._plugin_classes[plugin_name]
            plugin = plugin_class()
            
            # Initialize
            await plugin.initialize()
            
            self._plugins[plugin_name] = plugin
            logger.info(f"Loaded plugin: {plugin_name} v{plugin.version}")
            
            return True
        
        except Exception as e:
            logger.error(f"Error loading plugin {plugin_name}: {e}")
            return False
    
    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name not in self._plugins:
            logger.warning(f"Plugin not loaded: {plugin_name}")
            return False
        
        try:
            plugin = self._plugins[plugin_name]
            await plugin.cleanup()
            del self._plugins[plugin_name]
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True
        
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_name}: {e}")
            return False
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin (hot-reload)"""
        logger.info(f"Reloading plugin: {plugin_name}")
        
        if plugin_name in self._plugins:
            await self.unload_plugin(plugin_name)
        
        # Remove from cache
        if plugin_name in self._plugin_classes:
            del self._plugin_classes[plugin_name]
        
        # Rediscover and load
        self.discover_plugins()
        return await self.load_plugin(plugin_name)
    
    def get_plugin(self, plugin_name: str) -> PluginBase:
        """Get a loaded plugin"""
        return self._plugins.get(plugin_name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins"""
        plugins = []
        
        for name, plugin in self._plugins.items():
            plugins.append({
                'name': plugin.name,
                'version': plugin.version,
                'description': plugin.description,
                'loaded': True
            })
        
        return plugins
    
    def list_available_plugins(self) -> List[str]:
        """List all available (but not necessarily loaded) plugins"""
        return list(self._plugin_classes.keys())
    
    async def load_all_plugins(self):
        """Load all discovered plugins"""
        discovered = self.discover_plugins()
        
        for plugin_name in discovered:
            await self.load_plugin(plugin_name)
    
    async def unload_all_plugins(self):
        """Unload all plugins"""
        for plugin_name in list(self._plugins.keys()):
            await self.unload_plugin(plugin_name)


# Global plugin manager instance
plugin_manager = PluginManager()


# Example plugin (for demonstration)
class ExampleScannerPlugin(ScannerPlugin):
    """Example scanner plugin"""
    
    @property
    def name(self) -> str:
        return "Example Scanner"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "An example scanner plugin for demonstration"
    
    async def initialize(self):
        logger.info(f"Initializing {self.name}")
    
    async def cleanup(self):
        logger.info(f"Cleaning up {self.name}")
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'target': target,
            'results': [],
            'status': 'completed'
        }
