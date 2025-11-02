# plugins/plugin_base.py
from abc import ABC, abstractmethod

class PluginBase(ABC):
    @property
    @abstractmethod
    def name(self): pass

    @abstractmethod
    def run(self, targets, config):
        pass
