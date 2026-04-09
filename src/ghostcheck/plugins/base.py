from abc import ABC, abstractmethod

class BasePlugin(ABC):
    """
    Base class for all GhostCheck plugins.
    Plugins should inherit from this class and implement the scan method.
    """
    
    @abstractmethod
    def scan(self, file_path, content):
        """
        Scan a file and return a list of findings.
        A finding should be a dictionary with keys: file, line, name, severity, suggestion.
        """
        pass

    @property
    @abstractmethod
    def name(self):
        """Return the name of the plugin."""
        pass
