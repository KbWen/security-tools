import re
import os

class FirebaseRulesAuditor:
    def __init__(self):
        self.rules_patterns = [
            {
                "name": "firebase_allow_all_read",
                "pattern": r'allow\s+([^:]*read[^:]*)\s*:\s*if\s+true',
                "severity": "CRITICAL",
                "suggestion": "Rule permits anyone to read all data. Restrict access based on authentication."
            },
            {
                "name": "firebase_allow_all_write",
                "pattern": r'allow\s+([^:]*write[^:]*)\s*:\s*if\s+true',
                "severity": "CRITICAL",
                "suggestion": "Rule permits anyone to write/delete data. Restrict access strictly with auth checks."
            },
            {
                "name": "firebase_missing_auth_check",
                "pattern": r'allow\s+(read|write|create|update|delete).*[^!]=\s*null', # Simplified check
                "severity": "HIGH",
                "suggestion": "Ensure rules contain proper request.auth != null checks for non-public data."
            },
            {
                "name": "rtdb_allow_all",
                "pattern": r'"\.(read|write)"\s*:\s*true', # Realtime DB JSON rules
                "severity": "CRITICAL",
                "suggestion": "Realtime Database is wide open. Use \".read\": \"auth != null\" at minimum."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        is_rules = file_path.endswith('.rules') or 'database.rules.json' in file_path
        if not is_rules:
            return []
            
        for i, line in enumerate(lines):
            for p in self.rules_patterns:
                if re.search(p['pattern'], line):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
                    })
        return findings
