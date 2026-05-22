import abc
from typing import List, Dict, Any

class BaseScannerPlugin(abc.ABC):
    """
    Base interface for all GhostCheck scanner plugins.
    """
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Return the unique name of the plugin."""
        pass
        
    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Return a short description of what the plugin does."""
        pass

    @abc.abstractmethod
    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        """
        Perform the scan on the given files.
        
        Args:
            files: A list of absolute file paths to scan.
            config: GhostCheckConfig instance (or dict) with scanning context.
            
        Returns:
            A list of findings (dictionaries).
        """
        pass


class BaseReporterPlugin(abc.ABC):
    """
    Base interface for all GhostCheck reporter plugins.
    """
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Return the unique name of the reporter format (e.g. 'json', 'owasp')."""
        pass

    @abc.abstractmethod
    def report(self, findings: List[Dict[str, Any]], stream=None, **kwargs) -> None:
        """
        Format and output the findings.
        
        Args:
            findings: A list of dictionaries representing the scan findings.
            stream: A file-like object to write the output to. If None, prints to stdout.
            kwargs: Additional reporter-specific parameters (e.g. grade, output_path).
        """
        pass
