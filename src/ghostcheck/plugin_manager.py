import os
import sys
import importlib
import pkgutil
import inspect
from typing import Dict, Type, List, Any

from .interfaces import BaseScannerPlugin, BaseReporterPlugin

class PluginManager:
    def __init__(self):
        self._scanners: Dict[str, Type[BaseScannerPlugin]] = {}
        self._reporters: Dict[str, Type[BaseReporterPlugin]] = {}

    def load_builtins(self):
        """Discover and load all built-in plugins from checks/ and reporters/ directories."""
        self._load_from_package('ghostcheck.checks', BaseScannerPlugin, self._scanners)
        self._load_from_package('ghostcheck.reporters', BaseReporterPlugin, self._reporters)

    def _load_from_package(self, package_name: str, interface_class: Type, registry: Dict[str, Type]):
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return

        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            full_module_name = f"{package_name}.{module_name}"
            try:
                module = importlib.import_module(full_module_name)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a concrete subclass of the interface
                    if issubclass(obj, interface_class) and obj is not interface_class and not inspect.isabstract(obj):
                        try:
                            # Instantiate temporarily to get the name property if it's dynamic
                            # or just try to grab a class property/method
                            instance = obj()
                            plugin_name = getattr(instance, 'name', name.lower())
                            registry[plugin_name] = obj
                        except Exception as e:
                            # Fallback to class name if instantiation requires args
                            registry[name.lower()] = obj
            except Exception as e:
                # Log or ignore bad modules
                pass

    def get_scanner(self, name: str) -> Type[BaseScannerPlugin]:
        return self._scanners.get(name)

    def get_all_scanners(self) -> Dict[str, Type[BaseScannerPlugin]]:
        return self._scanners

    def get_reporter(self, name: str) -> Type[BaseReporterPlugin]:
        return self._reporters.get(name)

    def get_all_reporters(self) -> Dict[str, Type[BaseReporterPlugin]]:
        return self._reporters
