import os
import sys

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print("Error: Missing dependency 'tomli'. Please install it using 'pip install tomli'.")
        sys.exit(1)
from typing import Dict, Any, Optional


class GhostCheckConfig:
    DEFAULT_CONFIG = {
        "severity_threshold": "INFO",
        "exclude_patterns": [],
        "enabled_checks": ["hallucination", "secrets", "rules", "docker"],
        "offline": False,
        "custom_patterns": [],
        "load_local_plugins": False,
        "proxy": None,
        "ssl_verify": True,
        "custom_safe_keywords": [],
        "custom_example_keywords": [],
        "preset": None,
        "timeout": 10
    }

    def __init__(self, project_root: str):
        self.project_root = os.path.abspath(project_root)
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_all_configs()

    def _load_all_configs(self):
        # 1. Load Global Config (~/.ghostcheck/config.toml)
        global_config_path = os.path.expanduser("~/.ghostcheck/config.toml")
        if os.path.exists(global_config_path):
            self._merge_config(self._read_toml(global_config_path))

        # 2. Upward search for project config
        current = os.path.abspath(self.project_root)
        search_paths = []
        
        while True:
            search_paths.append(current)
            # Stop at root or if we find .git (likely project root)
            if os.path.exists(os.path.join(current, ".git")):
                break
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
            
        for path in reversed(search_paths):  # From top to bottom to allow overrides
            # Check for ghostcheck.toml
            project_config_path = os.path.join(path, "ghostcheck.toml")
            if os.path.exists(project_config_path):
                self._merge_config(self._read_toml(project_config_path))
                
            # Check pyproject.toml
            pyproject_path = os.path.join(path, "pyproject.toml")
            if os.path.exists(pyproject_path):
                pyproject_data = self._read_toml(pyproject_path)
                if "tool" in pyproject_data and "ghostcheck" in pyproject_data["tool"]:
                    self._merge_config(pyproject_data["tool"]["ghostcheck"])

    def _read_toml(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "rb") as f:
                return tomllib.load(f)
        except Exception:
            return {}

    def _merge_config(self, new_data: Dict[str, Any]):
        if not new_data:
            return
        
        # Simple merge for keys
        for key in self.DEFAULT_CONFIG.keys():
            if key in new_data:
                if isinstance(self.config[key], list) and isinstance(new_data[key], list):
                    # 確保列表項目唯一，且處理非雜湊物件
                    seen = []
                    combined = self.config[key] + new_data[key]
                    for item in combined:
                        if item not in seen:
                            seen.append(item)
                    self.config[key] = seen
                else:
                    if key == 'timeout':
                        timeout_val = new_data[key]
                        if timeout_val is not None:
                            if type(timeout_val) is not int or timeout_val <= 0:
                                raise ValueError("Timeout must be a positive integer.")
                    self.config[key] = new_data[key]

    def get_canary_url(self) -> Optional[str]:
        # Search upward for ghostcheck.toml or pyproject.toml
        current = os.path.abspath(self.project_root)
        search_paths = []
        while True:
            search_paths.append(current)
            if os.path.exists(os.path.join(current, ".git")):
                break
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
            
        for path in reversed(search_paths):
            # Check ghostcheck.toml
            toml_path = os.path.join(path, "ghostcheck.toml")
            if os.path.exists(toml_path):
                data = self._read_toml(toml_path)
                url = data.get("tool", {}).get("ghostcheck", {}).get("honeypot", {}).get("canary_url")
                if url:
                    return url
                url = data.get("honeypot", {}).get("canary_url")
                if url:
                    return url
                
            # Check pyproject.toml
            pyproject_path = os.path.join(path, "pyproject.toml")
            if os.path.exists(pyproject_path):
                data = self._read_toml(pyproject_path)
                if "tool" in data and "ghostcheck" in data["tool"]:
                    url = data["tool"]["ghostcheck"].get("honeypot", {}).get("canary_url")
                    if url:
                        return url
        return None

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def update_from_args(self, args: Any):
        """Overrides config with CLI arguments."""
        if hasattr(args, 'severity') and args.severity:
            self.config['severity_threshold'] = args.severity
        if hasattr(args, 'offline') and args.offline:
            self.config['offline'] = True
        if hasattr(args, 'load_local_plugins') and args.load_local_plugins:
            self.config['load_local_plugins'] = True
        if hasattr(args, 'insecure') and args.insecure:
            self.config['ssl_verify'] = False
        if hasattr(args, 'preset') and args.preset:
            self.config['preset'] = args.preset
        if hasattr(args, 'timeout') and args.timeout is not None:
            if type(args.timeout) is not int or args.timeout <= 0:
                raise ValueError("Timeout must be a positive integer.")
            self.config['timeout'] = args.timeout
