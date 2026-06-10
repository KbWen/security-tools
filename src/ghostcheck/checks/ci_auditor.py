import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class CIAuditor(BaseScannerPlugin):
    def __init__(self):
        # GitHub Actions patterns
        self.gha_patterns = [
            {
                "name": "gha_write_all_permission",
                "pattern": r'permissions:\s*(?:["\']?write-all["\']?|\n\s+.*write-all)',
                "severity": "HIGH",
                "suggestion": "Use least-privilege permissions (read-only or specific resource scopes) instead of write-all."
            },
            {
                "name": "gha_pull_request_target_risk",
                "pattern": r'(?:on:\s*(?:\[\s*|.*?\n\s+(?:-\s+)?)?|on:\s+)pull_request_target',
                "severity": "MEDIUM",
                "suggestion": "Be very careful with pull_request_target. Ensure you are not checking out untrusted code from fork with secrets."
            },
            {
                "name": "gha_unpinned_action",
                "pattern": r'uses:\s*[^@\s]+@(?![a-fA-F0-9]{40}\b)[a-zA-Z0-9_./-]+', # Flags any mutable tag/branch (not 40-char SHA)
                "severity": "LOW",
                "suggestion": "Pin actions to specific commit SHAs for supply chain security."
            },
            {
                "name": "gha_secret_exposure_in_run",
                "pattern": r'echo\s+(?:["\']?\$[^"\'\s]+["\']?|\$\{\{\s*secrets\.[^\}]+\s*\}\})', # Potential secret echo, quoted or unquoted or GHA expression
                "severity": "MEDIUM",
                "suggestion": "Avoid echoing secrets or using them directly in shell scripts. Use them as env vars if needed."
            }
        ]
        
        # GitLab CI patterns
        self.gitlab_patterns = [
            {
                "name": "gitlab_privileged_runner",
                "pattern": r'privileged:\s*true',
                "severity": "HIGH",
                "suggestion": "Running privileged GitLab CI runners introduces security risks."
            },
            {
                "name": "gitlab_secret_exposure_in_run",
                "pattern": r'echo\s+["\']\$[^"\']+["\']',
                "severity": "MEDIUM",
                "suggestion": "Avoid echoing secrets or using them directly in shell scripts. Use them as env vars if needed."
            }
        ]
        
        # Mobile CI (Fastlane) patterns
        self.mobile_ci_patterns = [
            {
                "name": "fastlane_hardcoded_password",
                "pattern": r'(password|api_key|token)\s*[:=]\s*["\'][^"\']+["\']',
                "severity": "HIGH",
                "suggestion": "Use environment variables or Fastlane Match for credentials."
            },
            {
                "name": "fastlane_match_git_url_missing",
                "pattern": r'match.*git_url', # Just a presence check for now
                "severity": "INFO",
                "suggestion": "Ensure Fastlane Match is using a secure private repository."
            }
        ]

    @property
    def name(self) -> str:
        return "ci_auditor"

    @property
    def description(self) -> str:
        return "Scans CI/CD pipelines (GitHub Actions, GitLab CI, Fastlane) for security risks."

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            path_lower = file_path.replace('\\', '/').lower()
            filename = path_lower.split('/')[-1]
            is_ci = any(x in path_lower for x in ['.github/workflows', '.gitlab-ci', 'fastfile', 'matchfile', 'appfile'])
            is_mobile_cfg = any(k in filename for k in ['key.properties', 'googleservice-info.plist', 'google-services.json'])
            
            if is_ci or is_mobile_cfg:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    findings.extend(self.scan_file(file_path, content))
                except Exception:
                    pass
        return findings

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        path_lower = file_path.replace('\\', '/').lower()
        is_gha = ".github/workflows" in path_lower
        is_gitlab = ".gitlab-ci" in path_lower
        is_fastlane = "fastfile" in path_lower or "matchfile" in path_lower or "appfile" in path_lower
        
        patterns = []
        if is_gha:
            patterns = self.gha_patterns
        elif is_gitlab:
            patterns = self.gitlab_patterns
        elif is_fastlane:
            patterns = self.mobile_ci_patterns
            
        for p in patterns:
            # Use dotall to handle multiline YAML constructs for specific patterns
            flags = re.IGNORECASE | re.DOTALL if p['name'] in ["gha_write_all_permission", "gha_pull_request_target_risk"] else re.IGNORECASE
            for match in re.finditer(p['pattern'], content, flags):
                start_offset = match.start()
                
                # Filter out comments
                line_start = content.rfind('\n', 0, start_offset) + 1
                line_end = content.find('\n', start_offset)
                if line_end == -1:
                    line_end = len(content)
                current_line = content[line_start:line_end].strip()
                if current_line.startswith('#'):
                    continue

                line_idx = content.count('\n', 0, start_offset)
                context_preview = content[max(0, start_offset - 10):min(len(content), match.end() + 10)].replace('\n', ' ')
                
                findings.append({
                    "file": file_path,
                    "line": line_idx + 1,
                    "name": p['name'],
                    "severity": p['severity'],
                    "suggestion": p['suggestion'],
                    "context": context_preview.strip()
                })
                    
        # Critical: check if signing keys are committed
        mobile_keys = ['key.properties', 'googleservice-info.plist', 'google-services.json']
        if any(k in path_lower for k in mobile_keys) and not path_lower.endswith('.gitignore'):
             findings.append({
                "file": file_path,
                "line": 1,
                "name": "sensitive_mobile_config_found",
                "severity": "HIGH",
                "suggestion": "Mobile signing configs or service descriptors should not be committed to public repositories.",
                "context": "File detected: " + os.path.basename(file_path)
            })

        return findings
