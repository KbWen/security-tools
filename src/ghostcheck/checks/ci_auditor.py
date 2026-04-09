import re
import os

class CIAuditor:
    def __init__(self):
        # GitHub Actions patterns
        self.gha_patterns = [
            {
                "name": "gha_write_all_permission",
                "pattern": r'permissions:\s*write-all',
                "severity": "HIGH",
                "suggestion": "Use least-privilege permissions (read-only or specific resource scopes) instead of write-all."
            },
            {
                "name": "gha_pull_request_target_risk",
                "pattern": r'on:\s*pull_request_target',
                "severity": "MEDIUM",
                "suggestion": "Be very careful with pull_request_target. Ensure you are not checking out untrusted code from fork with secrets."
            },
            {
                "name": "gha_unpinned_action",
                "pattern": r'uses:\s*[^@]+@(main|master|v\d+)', # Matches @main or @v1
                "severity": "LOW",
                "suggestion": "Pin actions to specific commit SHAs for supply chain security."
            },
            {
                "name": "gha_secret_exposure_in_run",
                "pattern": r'echo\s+["\']\$[^"\']+["\']', # Potential secret echo
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

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        is_gha = ".github/workflows" in file_path.replace('\\', '/')
        is_gitlab = ".gitlab-ci" in file_path
        is_fastlane = "Fastfile" in file_path or "Matchfile" in file_path or "Appfile" in file_path
        
        patterns = []
        if is_gha:
            patterns = self.gha_patterns
        elif is_gitlab:
            patterns = self.gitlab_patterns
        elif is_fastlane:
            patterns = self.mobile_ci_patterns
            
        for i, line in enumerate(lines):
            for p in patterns:
                if re.search(p['pattern'], line):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
                    })
                    
        # Critical: check if signing keys are committed
        mobile_keys = ['key.properties', 'GoogleService-Info.plist', 'google-services.json']
        if any(k in file_path for k in mobile_keys) and not file_path.endswith('.gitignore'):
             findings.append({
                "file": file_path,
                "line": 1,
                "name": "sensitive_mobile_config_found",
                "severity": "HIGH",
                "suggestion": "Mobile signing configs or service descriptors should not be committed to public repositories.",
                "context": "File detected: " + os.path.basename(file_path)
            })

        return findings
