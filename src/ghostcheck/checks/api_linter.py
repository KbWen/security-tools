import re

class APILinter:
    def __init__(self):
        self.rules = [
            {
                "name": "api_cors_wildcard",
                "pattern": r'Access-Control-Allow-Origin.*[\'"]\*[\'"]',
                "severity": "HIGH",
                "message": "CORS wildcard (*) detected. This allows any domain to access your API.",
                "remediation": "Restrict CORS to specific trusted origins."
            },
            {
                "name": "api_csrf_disabled",
                "pattern": r'(csrf_enabled|enable_csrf).*=.*(false|False|0)',
                "severity": "HIGH",
                "message": "CSRF protection appears to be disabled.",
                "remediation": "Enable CSRF protection for session-based APIs."
            },
            {
                "name": "api_graphql_introspection_enabled",
                "pattern": r'(introspection).*=.*(true|True|1)',
                "severity": "MEDIUM",
                "message": "GraphQL introspection is enabled in what might be a production config.",
                "remediation": "Disable introspection in production to prevent schema leakage."
            }
        ]

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
