import json
import re
import urllib.request
import urllib.error
import time
from datetime import datetime

class HallucinationChecker:
    def __init__(self, logger=None):
        self.logger = logger

    def check_requirements(self, file_content):
        findings = []
        packages = self._parse_requirements(file_content)
        for pkg in packages:
            result = self._check_pypi(pkg)
            if result:
                findings.append(result)
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
                result = self._check_npm(pkg)
                if result:
                    findings.append(result)
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

    def _check_pypi(self, pkg_name):
        url = f"https://pypi.org/pypi/{pkg_name}/json"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode())
                info = data.get('info', {})
                releases = data.get('releases', {})
                
                # Get creation date (upload time of first release)
                upload_times = []
                for rel in releases.values():
                    for entry in rel:
                        upload_times.append(entry.get('upload_time'))
                
                created_at = None
                if upload_times:
                    created_at = min(upload_times)
                
                # Check metrics (simulated download count as PyPI API doesn't provide it directly in /json)
                # We'll use version count or other signals if available, but for MVP we focus on age.
                if created_at:
                    age_days = (datetime.now() - datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S')).days
                    if age_days < 30:
                        return {"package": pkg_name, "registry": "PyPI", "severity": "HIGH", "message": f"Package is very new ({age_days} days old). Potential hallucination or typosquatting."}
                    elif age_days < 90:
                        return {"package": pkg_name, "registry": "PyPI", "severity": "MEDIUM", "message": f"Package is relatively new ({age_days} days old)."}
                
                # Note: PyPI /json API doesn't provide download counts. 
                # Weekly download checks currently skipped in zero-dependency MVP.
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"package": pkg_name, "registry": "PyPI", "severity": "CRITICAL", "message": "Package does not exist on PyPI. High risk of AI hallucination."}
        except Exception:
            pass
        return None

    def _check_npm(self, pkg_name):
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
                
                # Note: npm registry requires separate API for downloads.
                # Weekly download checks currently skipped in zero-dependency MVP.
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"package": pkg_name, "registry": "npm", "severity": "CRITICAL", "message": "Package does not exist on npm registry."}
        except Exception:
            pass
        return None
