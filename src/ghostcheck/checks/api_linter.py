import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class APILinter(BaseScannerPlugin):
    def __init__(self):
        # Prevent ReDoS using non-greedy limited-length matching [\s\S]{0,N}?
        # This also supports matching configs split across lines.
        self.rules = [
            {
                "name": "api_cors_wildcard",
                "pattern": re.compile(r'\b(?:Access-Control-Allow-Origin|origins?|allow_origins?)[\s\S]{0,100}?[`\'"]\*[`\'"]', re.IGNORECASE),
                "severity": "HIGH",
                "message": "CORS wildcard (*) detected. This allows any domain to access your API.",
                "remediation": "Restrict CORS to specific trusted origins."
            },
            {
                "name": "api_csrf_disabled",
                "pattern": re.compile(r'\b(?:csrf_enabled|enable_csrf)[\s\S]{0,50}?[:=]\s*(?:false|0)\b', re.IGNORECASE),
                "severity": "HIGH",
                "message": "CSRF protection appears to be disabled.",
                "remediation": "Enable CSRF protection for session-based APIs."
            },
            {
                "name": "api_graphql_introspection_enabled",
                "pattern": re.compile(r'\bintrospection\b[\s\S]{0,50}?[:=]\s*(?:true|1)\b', re.IGNORECASE),
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
        allowed_exts = ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.kt', '.php', '.rb', '.cs', '.json', '.yaml', '.yml', '.toml']
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
            matches = rule['pattern'].finditer(content)
            for match in matches:
                start_offset = match.start()
                
                # Filter out comments
                line_start = content.rfind('\n', 0, start_offset) + 1
                line_end = content.find('\n', start_offset)
                if line_end == -1:
                    line_end = len(content)
                current_line = content[line_start:line_end].strip()
                if current_line.startswith(('#', '//', '/*', '*')):
                    continue
                    
                line_idx = content.count('\n', 0, start_offset) + 1
                matched_text = match.group(0).strip()
                context_snippet = matched_text.splitlines()[0] if matched_text else ""
                if len(context_snippet) > 100:
                    context_snippet = context_snippet[:97] + "..."
                    
                findings.append({
                    "file": file_path,
                    "line": line_idx,
                    "name": rule['name'],
                    "severity": rule['severity'],
                    "message": rule['message'],
                    "remediation": rule['remediation'],
                    "context": context_snippet
                })
        return findings
