import os
import json
import re
import urllib.request
import urllib.error
import time
from datetime import datetime, timedelta
import hashlib

class HallucinationChecker:
    def __init__(self, logger=None, offline=False):
        self.logger = logger
        self.offline = offline
        self.cache_dir = os.path.expanduser("~/.ghostcheck/cache")
        self.cache_file = os.path.join(self.cache_dir, "hallucination.json")
        self._load_cache()

    def _load_cache(self):
        self.cache = {}
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    content = f.read()
                    data = json.loads(content)
                    # Verify integrity if hash exists
                    if 'integrity' in data:
                        stored_hash = data.pop('integrity')
                        current_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
                        if stored_hash != current_hash:
                            if self.logger: self.logger.warning("Cache integrity check failed. Involving new cache.")
                            self.cache = {}
                            return
                    self.cache = data
            except (json.JSONDecodeError, IOError):
                pass

    def _save_cache(self):
        try:
            if not os.path.exists(self.cache_dir):
                os.makedirs(self.cache_dir, exist_ok=True)
            
            # Add integrity hash before saving
            cache_to_save = self.cache.copy()
            if 'integrity' in cache_to_save:
                del cache_to_save['integrity']
            
            integrity_hash = hashlib.sha256(json.dumps(cache_to_save, sort_keys=True).encode()).hexdigest()
            cache_to_save['integrity'] = integrity_hash

            with open(self.cache_file, 'w') as f:
                json.dump(cache_to_save, f)
        except IOError:
            pass

    def _get_cached(self, registry, pkg_name):
        key = f"{registry}:{pkg_name}"
        if key in self.cache:
            entry = self.cache[key]
            try:
                cached_time = datetime.fromisoformat(entry['timestamp'])
                is_stale = datetime.now() - cached_time > timedelta(hours=24)
                
                if not is_stale:
                    return entry['data'], False
                elif self.offline:
                    # Stale but in offline mode, return with warning flag
                    return entry['data'], True
            except (ValueError, KeyError):
                pass
        return None, False

    def _set_cached(self, registry, pkg_name, data):
        key = f"{registry}:{pkg_name}"
        self.cache[key] = {
            "timestamp": datetime.now().isoformat(),
            "data": data
        }
        self._save_cache()

    def check_requirements(self, file_content):
        findings = []
        packages = self._parse_requirements(file_content)
        for pkg in packages:
            result = self._check_package("PyPI", pkg)
            if result:
                findings.append(result)
            if not self.offline:
                time.sleep(0.5)  # Rate limiting
        return findings

    def check_package_json(self, file_content):
        findings = []
        try:
            data = json.loads(file_content)
            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})
            all_deps = {**deps, **dev_deps}
            
            for pkg in all_deps:
                result = self._check_package("npm", pkg)
                if result:
                    findings.append(result)
                if not self.offline:
                    time.sleep(0.5)  # Rate limiting
        except json.JSONDecodeError:
            pass
        return findings

    def _parse_requirements(self, content):
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Basic parsing: name[==version]
            match = re.match(r'^([a-zA-Z0-9._-]+)', line)
            if match:
                packages.append(match.group(1))
        return packages

    def _check_package(self, registry, pkg_name):
        # 1. Check Cache
        cached_data, is_stale = self._get_cached(registry, pkg_name)
        if cached_data is not None:
            if is_stale and self.offline:
                # In a real CLI, we might want to collect these and show at the end
                # For now, we return it but it's marked as potentially stale
                pass 
            return cached_data if cached_data != "OK" else None

        # 2. If Offline and not in cache, skip
        if self.offline:
            return None

        # 3. Perform real network check
        if registry == "PyPI":
            result = self._check_pypi_online(pkg_name)
        else:
            result = self._check_npm_online(pkg_name)

        # 4. Update Cache (store "OK" if no finding)
        self._set_cached(registry, pkg_name, result if result else "OK")
        return result

    def _check_pypi_online(self, pkg_name):
        url = f"https://pypi.org/pypi/{pkg_name}/json"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode())
                info = data.get('info', {})
                releases = data.get('releases', {})
                
                upload_times = []
                for rel in releases.values():
                    for entry in rel:
                        upload_times.append(entry.get('upload_time'))
                
                created_at = None
                if upload_times:
                    created_at = min(upload_times)
                
                if created_at:
                    age_days = (datetime.now() - datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S')).days
                    if age_days < 30:
                        return {"package": pkg_name, "registry": "PyPI", "severity": "HIGH", "message": f"Package is very new ({age_days} days old). Potential hallucination or typosquatting."}
                    elif age_days < 90:
                        return {"package": pkg_name, "registry": "PyPI", "severity": "MEDIUM", "message": f"Package is relatively new ({age_days} days old)."}
                
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"package": pkg_name, "registry": "PyPI", "severity": "CRITICAL", "message": "Package does not exist on PyPI. High risk of AI hallucination."}
        except Exception:
            pass
        return None

    def _check_npm_online(self, pkg_name):
        url = f"https://registry.npmjs.org/{pkg_name}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                time_data = data.get('time', {})
                created_at_str = time_data.get('created')
                
                if created_at_str:
                    created_at = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                    age_days = (datetime.now() - created_at).days
                    if age_days < 30:
                        return {"package": pkg_name, "registry": "npm", "severity": "HIGH", "message": f"Package is very new ({age_days} days old)."}
                    elif age_days < 90:
                        return {"package": pkg_name, "registry": "npm", "severity": "MEDIUM", "message": f"Package is relatively new ({age_days} days old)."}
                
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"package": pkg_name, "registry": "npm", "severity": "CRITICAL", "message": "Package does not exist on npm registry."}
        except Exception:
            pass
        return None
