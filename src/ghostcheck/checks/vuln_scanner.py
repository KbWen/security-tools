import json
try:
    import requests
except ImportError:
    requests = None
import os
import logging
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

class VulnScanner(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "vulnscanner"

    @property
    def description(self) -> str:
        return "Scanner plugin for VulnScanner"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            filename = os.path.basename(file_path).lower()
            if filename not in ["requirements.txt", "package.json"]:
                continue
            try:
                findings.extend(self.scan_file(file_path))
            except Exception:
                pass
        return findings

    OSV_API_URL = "https://api.osv.dev/v1/query"

    def __init__(self, offline=False, proxy=None, ssl_verify=True, timeout=10):
        self.offline = offline
        self.proxy = proxy
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def _query_osv(self, package_name, version, ecosystem):
        if self.offline or requests is None:
            return None
        
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        try:
            response = requests.post(
                self.OSV_API_URL, 
                json=payload, 
                timeout=self.timeout, 
                proxies=self.proxies,
                verify=self.ssl_verify
            )
            if response.status_code == 200:
                return response.json()
        except requests.RequestException as e:
            # Silently fail on network errors but could log here in debug mode
            logger.debug(f"OSV API request failed: {e}")
            if os.environ.get("GHOSTCHECK_DEBUG") == "1":
                print(f"[DEBUG] Vulnerability scan network error. If you are offline, use --offline. Error: {e}")
        return None

    def scan_file(self, file_path):
        findings = []
        filename = os.path.basename(file_path)
        
        if filename == "requirements.txt":
            findings.extend(self._scan_requirements(file_path))
        elif filename == "package.json":
            findings.extend(self._scan_package_json(file_path))
            
        return findings

    def _scan_requirements(self, file_path):
        findings = []
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Simple parser for name==version
                parts = line.split('==')
                if len(parts) == 2:
                    name, version = parts[0].strip(), parts[1].strip()
                    res = self._query_osv(name, version, "PyPI")
                    if res and 'vulns' in res:
                        for v in res['vulns']:
                            findings.append({
                                "file": file_path,
                                "line": i + 1,
                                "name": "cve_dependency_vulnerability",
                                "severity": "HIGH",
                                "package": name,
                                "version": version,
                                "vuln_id": v.get('id'),
                                "message": f"Vulnerability {v.get('id')} found in {name}=={version}: {v.get('summary', 'No summary available')}",
                                "remediation": f"Update {name} to a fixed version."
                            })
        return findings

    def _scan_package_json(self, file_path):
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
                deps = data.get('dependencies', {})
                if not isinstance(deps, dict): deps = {}
                dev_deps = data.get('devDependencies', {})
                if not isinstance(dev_deps, dict): dev_deps = {}
                for name, version in {**deps, **dev_deps}.items():
                    if not isinstance(version, str):
                        continue
                    # Clean version (strip ^, ~)
                    clean_version = version.lstrip('^~<>=').split(' ')[0]
                    res = self._query_osv(name, clean_version, "npm")
                    if res and 'vulns' in res:
                        for v in res['vulns']:
                            findings.append({
                                "file": file_path,
                                "line": 0, # JSON level
                                "name": "cve_dependency_vulnerability",
                                "severity": "HIGH",
                                "package": name,
                                "version": clean_version,
                                "vuln_id": v.get('id'),
                                "message": f"Vulnerability {v.get('id')} found in npm package {name}@{clean_version}: {v.get('summary')}",
                                "remediation": f"Update npm package {name} to a fixed version."
                            })
        except Exception as e:
            # Log file parsing errors
            logger.debug(f"Error parsing package.json: {file_path} - {e}")
        return findings
