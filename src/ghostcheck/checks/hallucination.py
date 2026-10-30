import os
import json
import re
import urllib.request
import urllib.error
import urllib.parse
import time
from datetime import datetime, timedelta
import hashlib
import threading
import logging
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

class HallucinationChecker(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "hallucinationchecker"

    @property
    def description(self) -> str:
        return "Scanner plugin for HallucinationChecker"

    def _find_pkg_line(self, content: str, pkg_name: str) -> int:
        if not content or not pkg_name:
            return 1
        for idx, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if pkg_name in stripped:
                return idx
        return 1

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                filename = file_path.replace('\\', '/').split('/')[-1]
                file_findings = []
                if filename == 'requirements.txt':
                    file_findings = self.check_requirements(content)
                elif filename == 'package.json':
                    file_findings = self.check_package_json(content)

                for fnd in file_findings:
                    if isinstance(fnd, dict):
                        fnd_copy = fnd.copy()
                        fnd_copy.setdefault('file', file_path)
                        fnd_copy.setdefault('line', self._find_pkg_line(content, fnd_copy.get('package', '')))
                        fnd_copy.setdefault('name', 'hallucinated_package')
                        findings.append(fnd_copy)

            except Exception:
                pass
        return findings

    def __init__(self, logger=None, offline=False, proxy=None, ssl_verify=True, timeout=10):
        self.logger = logger
        self.offline = offline
        self.proxy = proxy
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.opener = None
        self.cache_dir = os.path.expanduser("~/.ghostcheck/cache")
        self.cache_file = os.path.join(self.cache_dir, "hallucination_v2.json")
        self._cache_lock = threading.Lock()
        self._last_status = None
        self._consecutive_net_failures = 0
        self._load_cache()
        self._setup_opener()

    def _setup_opener(self):
        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy}))
        
        opener = urllib.request.build_opener(*handlers)
        
        # AC-S1: Handle insecure SSL context
        if not self.ssl_verify:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Note: We need a custom handler for this
            https_handler = urllib.request.HTTPSHandler(context=context)
            opener.add_handler(https_handler)
            
        self.opener = opener
        if self.proxy or not self.ssl_verify:
            urllib.request.install_opener(opener)
        else:
            urllib.request.install_opener(None)

    def _load_cache(self):
        with self._cache_lock:
            self.cache = {}
            if os.path.exists(self.cache_file):
                try:
                    with open(self.cache_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        data = json.loads(content)
                        # Verify integrity if hash exists
                        if 'integrity' in data:
                            clean_data = data.copy()
                            stored_hash = clean_data.pop('integrity')
                            current_hash = hashlib.sha256(json.dumps(clean_data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                            if stored_hash != current_hash:
                                if self.logger: self.logger.warning("Cache integrity check failed. Involving new cache.")
                                self.cache = {}
                                return
                            data = clean_data
                        self.cache = data
                except (json.JSONDecodeError, IOError, OSError) as e:
                    logger.debug(f"Failed to load hallucination cache: {e}")

    def _save_cache(self):
        with self._cache_lock:
            self._save_cache_unlocked()

    def _save_cache_unlocked(self):
        try:
            if not os.path.exists(self.cache_dir):
                os.makedirs(self.cache_dir, exist_ok=True)
            
            # Add integrity hash before saving
            cache_to_save = self.cache.copy()
            if 'integrity' in cache_to_save:
                del cache_to_save['integrity']
            
            integrity_hash = hashlib.sha256(json.dumps(cache_to_save, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            cache_to_save['integrity'] = integrity_hash

            tmp_file = f"{self.cache_file}.tmp.{os.getpid()}.{threading.get_ident()}"
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(cache_to_save, f, separators=(',', ':'))
            os.replace(tmp_file, self.cache_file)
        except (IOError, OSError) as e:
            logger.debug(f"Failed to save hallucination cache: {e}")

    def _get_cached(self, registry, pkg_name):
        key = f"{registry}:{pkg_name}"
        with self._cache_lock:
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
                except (ValueError, KeyError, TypeError):
                    pass
        return None, False

    def _set_cached(self, registry, pkg_name, data):
        with self._cache_lock:
            self._set_cached_unlocked(registry, pkg_name, data)

    def _set_cached_unlocked(self, registry, pkg_name, data):
        key = f"{registry}:{pkg_name}"
        self.cache[key] = {
            "timestamp": datetime.now().isoformat(),
            "data": data
        }
        self._save_cache_unlocked()

    def check_requirements(self, file_content):
        findings = []
        packages = self._parse_requirements(file_content)
        for pkg in packages:
            result, network_called = self._check_package("PyPI", pkg)
            if result:
                findings.append(result)
        return findings

    def check_package_json(self, file_content):
        findings = []
        try:
            data = json.loads(file_content)
            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})
            all_deps = {**deps, **dev_deps}
            
            for pkg, ver in all_deps.items():
                # Filter out workspace, local, or git dependencies (e.g. workspace:*, file:..., link:..., portal:...)
                if isinstance(ver, str):
                    ver_clean = ver.strip().lower()
                    if (ver_clean.startswith('workspace:') or
                        ver_clean.startswith('file:') or
                        ver_clean.startswith('link:') or
                        ver_clean.startswith('portal:') or
                        ver_clean.startswith('git+') or
                        ver_clean.startswith('github:') or
                        '://' in ver_clean):
                        continue
                result, network_called = self._check_package("npm", pkg)
                if result:
                    findings.append(result)
        except json.JSONDecodeError:
            pass
        return findings

    def _parse_requirements(self, content):
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Handle editable installs (e.g. -e git+...#egg=requests)
            if line.startswith('-e') or line.startswith('--editable'):
                egg_match = re.search(r'#egg=([a-zA-Z0-9][a-zA-Z0-9._-]*)', line)
                if egg_match:
                    packages.append(egg_match.group(1))
                continue
            # Skip pip flags and options (e.g. --extra-index-url, -r, -c, -i, -f)
            if line.startswith(('--', '-r', '-c', '-i', '-f')):
                continue
            # Skip direct URLs or VCS references
            if any(line.startswith(prefix) for prefix in ('http://', 'https://', 'git+', 'hg+', 'svn+', 'bzr+', 'file:', './', '../')):
                continue
            # Strip trailing comments (whitespace preceding #)
            line = re.sub(r'\s+#.*$', '', line).strip()
            # Strip environment markers (; python_version >= ...) and hashes (--hash=...)
            line = line.split(';')[0].strip()
            line = line.split('--hash')[0].strip()
            # Standard PEP 508 package name: alphanumeric start, followed by alphanumeric, dot, underscore, or dash
            match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*)', line)
            if match:
                packages.append(match.group(1))
        return packages


    def _check_package(self, registry, pkg_name):
        # Filter out local files, git repository references, or direct URL dependencies
        if (not pkg_name or
            pkg_name.startswith('.') or
            pkg_name.startswith('file:') or
            pkg_name.startswith('git+') or
            '://' in pkg_name or
            pkg_name.startswith('http:') or
            pkg_name.startswith('https:')):
            return None, False

        # 1. Check Cache
        cached_data, is_stale = self._get_cached(registry, pkg_name)
        if cached_data is not None:
            return (cached_data if cached_data != "OK" else None), False

        # 2. If Offline and not in cache, skip
        if self.offline:
            return None, False

        # 3. Perform real network check
        local_status = "ERROR"
        if registry == "PyPI":
            result, local_status = self._check_pypi_online_status(pkg_name)
        elif registry == "npm":
            result, local_status = self._check_npm_online_status(pkg_name)
        elif registry == "crates":
            result, local_status = self._check_crates_online_status(pkg_name)
        else:
            result = None
            local_status = "ERROR"

        with self._cache_lock:
            self._last_status = local_status
            if local_status == "ERROR":
                self._consecutive_net_failures += 1
                if self._consecutive_net_failures >= 2:
                    self.offline = True
            else:
                self._consecutive_net_failures = 0

            # 4. Update Cache (Only cache confirmed HTTP 200 responses as "OK" and HTTP 404/findings; NEVER cache on network error!)
            if local_status == "OK":
                self._set_cached_unlocked(registry, pkg_name, result if result else "OK")
            elif local_status == "NOT_FOUND" and result:
                self._set_cached_unlocked(registry, pkg_name, result)
            elif result is not None:
                self._set_cached_unlocked(registry, pkg_name, result)

        return result, True

    def _check_pypi_online_status(self, pkg_name):
        safe_pkg = urllib.parse.quote(pkg_name)
        url = f"https://pypi.org/pypi/{safe_pkg}/json"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                status_code = getattr(response, 'status', getattr(response, 'code', 200))
                status = "OK" if status_code == 200 else "ERROR"
                data = json.loads(response.read().decode())
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
                        return {
                            "package": pkg_name, 
                            "registry": "PyPI", 
                            "severity": "HIGH", 
                            "message": f"Package is very new ({age_days} days old). Potential hallucination or typosquatting.",
                            "suggestion": "Verify the package author and source code before using."
                        }, status
                    elif age_days < 90:
                        return {
                            "package": pkg_name, 
                            "registry": "PyPI", 
                            "severity": "MEDIUM", 
                            "message": f"Package is relatively new ({age_days} days old).",
                            "suggestion": "Monitor for updates and community feedback."
                        }, status
                
                return None, status
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {
                    "package": pkg_name, 
                    "registry": "PyPI", 
                    "severity": "CRITICAL", 
                    "message": "Package does not exist on PyPI. High risk of AI hallucination.",
                    "suggestion": "Check for typos or hallucinated package names."
                }, "NOT_FOUND"
            return None, "ERROR"
        except Exception as e:
            logger.debug(f"PyPI check failed for {pkg_name}: {e}")
            return None, "ERROR"

    def _check_pypi_online(self, pkg_name):
        res, status = self._check_pypi_online_status(pkg_name)
        with self._cache_lock:
            self._last_status = status
        return res

    def _check_npm_online_status(self, pkg_name):
        safe_pkg = urllib.parse.quote(pkg_name, safe='@')
        url = f"https://registry.npmjs.org/{safe_pkg}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status_code = getattr(response, 'status', getattr(response, 'code', 200))
                status = "OK" if status_code == 200 else "ERROR"
                data = json.loads(response.read().decode())
                time_data = data.get('time', {})
                created_at_str = time_data.get('created')
                
                if created_at_str:
                    created_at = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                    age_days = (datetime.now() - created_at).days
                    if age_days < 30:
                        return {
                            "package": pkg_name, 
                            "registry": "npm", 
                            "severity": "HIGH", 
                            "message": f"Package is very new ({age_days} days old).",
                            "suggestion": "Verify the package author and source code."
                        }, status
                    elif age_days < 90:
                        return {
                            "package": pkg_name, 
                            "registry": "npm", 
                            "severity": "MEDIUM", 
                            "message": f"Package is relatively new ({age_days} days old).",
                            "suggestion": "Check community adoption and issue tracker."
                        }, status
                
                return None, status
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {
                    "package": pkg_name, 
                    "registry": "npm", 
                    "severity": "CRITICAL", 
                    "message": "Package does not exist on npm registry.",
                    "suggestion": "Check if the package name is correct or hallucinated."
                }, "NOT_FOUND"
            return None, "ERROR"
        except Exception as e:
            logger.debug(f"npm check failed for {pkg_name}: {e}")
            return None, "ERROR"

    def _check_npm_online(self, pkg_name):
        res, status = self._check_npm_online_status(pkg_name)
        with self._cache_lock:
            self._last_status = status
        return res

    def _check_crates_online_status(self, pkg_name):
        safe_pkg = urllib.parse.quote(pkg_name)
        url = f"https://crates.io/api/v1/crates/{safe_pkg}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'ghostcheck/1.3.0'})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status_code = getattr(response, 'status', getattr(response, 'code', 200))
                status = "OK" if status_code == 200 else "ERROR"
                data = json.loads(response.read().decode())
                crate = data.get('crate', {})
                created_at_str = crate.get('created_at')
                if created_at_str:
                    try:
                        clean_date = created_at_str.split('.')[0].rstrip('Z')
                        created_at = datetime.fromisoformat(clean_date)
                        age_days = (datetime.now() - created_at).days
                        if age_days < 30:
                            return {
                                "package": pkg_name,
                                "registry": "crates",
                                "severity": "HIGH",
                                "message": f"Package is very new ({age_days} days old). Potential hallucination or typosquatting.",
                                "suggestion": "Verify the crate author and source code before using."
                            }, status
                    except Exception as e:
                        logger.debug(f"Error parsing crate timestamp: {e}")
                return None, status
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {
                    "package": pkg_name,
                    "registry": "crates",
                    "severity": "CRITICAL",
                    "message": "Package does not exist on crates.io. High risk of AI hallucination.",
                    "suggestion": "Check for typos or hallucinated crate names."
                }, "NOT_FOUND"
            return None, "ERROR"
        except Exception as e:
            logger.debug(f"crates check failed for {pkg_name}: {e}")
            return None, "ERROR"

    def _check_crates_online(self, pkg_name):
        res, status = self._check_crates_online_status(pkg_name)
        with self._cache_lock:
            self._last_status = status
        return res
