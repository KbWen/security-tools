import os
import importlib.util
import sys
from .base import BasePlugin

class PluginLoader:
    def __init__(self, load_local=False, plugin_dirs=None):
        if plugin_dirs is not None:
            self.plugin_dirs = plugin_dirs
        else:
            self.plugin_dirs = [os.path.expanduser("~/.ghostcheck/plugins")]
            if load_local and os.environ.get("GHOSTCHECK_TRUST_WORKSPACE") == "1":
                self.plugin_dirs.append(os.path.join(os.getcwd(), ".ghostcheck", "plugins"))
            elif load_local:
                print("WARNING: Local plugins are disabled by default to prevent RCE. Set GHOSTCHECK_TRUST_WORKSPACE=1 to enable.", file=sys.stderr)
        self.plugins = []

    def load_plugins(self):
        self.plugins = []
        for p_dir in self.plugin_dirs:
            if not os.path.exists(p_dir):
                continue
            
            for filename in os.listdir(p_dir):
                if filename.endswith(".py") and filename != "__init__.py":
                    p_path = os.path.join(p_dir, filename)
                    plugin = self._load_from_file(p_path)
                    if plugin:
                        self.plugins.append(plugin)
        return self.plugins

    def _load_from_file(self, file_path):
        try:
            module_name = os.path.splitext(os.path.basename(file_path))[0]
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Find class that inherits from BasePlugin
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, BasePlugin) and 
                    attr is not BasePlugin):
                    return attr()
        except Exception as e:
            if os.environ.get("GHOSTCHECK_DEBUG") == "1":
                print(f"[DEBUG] Failed to load plugin {file_path}: {e}")
            pass
        return None

    def run_all(self, file_path, content):
        all_findings = []
        for plugin in self.plugins:
            try:
                findings = plugin.scan(file_path, content)
                if findings:
                    # Enrich with plugin name if not present
                    for f in findings:
                        if 'rule_name' not in f and 'name' not in f:
                            f['name'] = plugin.name
                    all_findings.extend(findings)
            except Exception as e:
                if os.environ.get("GHOSTCHECK_DEBUG") == "1":
                    print(f"[DEBUG] Plugin execution failed ({getattr(plugin, 'name', 'unknown')}): {e}")
                continue
        return all_findings
