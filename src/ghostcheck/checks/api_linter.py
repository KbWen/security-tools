import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class APILinter(BaseScannerPlugin):
    def __init__(self):
        self.rules = [
            {
                "name": "api_cors_wildcard",
                "pattern": r'Access-Control-Allow-Origin.*[`\'"]\*[`\'"]',
                "severity": "HIGH",
                "message": "CORS wildcard (*) detected. This allows any domain to access your API.",
                "remediation": "Restrict CORS to specific trusted origins."
            },
            {
                "name": "api_csrf_disabled",
                "pattern": r'(csrf_enabled|enable_csrf).*[:=].*(false|False|0)',
                "severity": "HIGH",
                "message": "CSRF protection appears to be disabled.",
                "remediation": "Enable CSRF protection for session-based APIs."
            },
            {
                "name": "api_graphql_introspection_enabled",
                "pattern": r'(introspection).*[:=].*(true|True|1)',
                "severity": "MEDIUM",
                "message": "GraphQL introspection is enabled in what might be a production config.",
                "remediation": "Disable introspection in production to prevent schema leakage."
            }
        ]

    @property
    def name(self) -> str:
        return "api_linter"

    @property
    def description(self) -> str:
        return "Scans API code for common security misconfigurations (CORS, CSRF, GraphQL introspection)."

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        allowed_exts = ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.kt', '.php', '.rb', '.cs']
        for file_path in files:
            filename = file_path.replace('\\', '/').split('/')[-1].lower()
            if not any(filename.endswith(ext) for ext in allowed_exts):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                findings.extend(self.scan_content(file_path, content))
            except Exception:
                pass
        return findings

    def scan_content(self, file_path, content):
        findings = []
        for rule in self.rules:
            matches = re.finditer(rule['pattern'], content, re.IGNORECASE)
            for match in matches:
                line_idx = content.count('\n', 0, match.start())
                findings.append({
                    "file": file_path,
                    "line": line_idx + 1,
                    "name": rule['name'],
                    "severity": rule['severity'],
                    "message": rule['message'],
                    "remediation": rule['remediation'],
                    "context": match.group(0).strip()
                })
        return findings
