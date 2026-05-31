import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class FirebaseRulesAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "firebaserulesauditor"

    @property
    def description(self) -> str:
        return "Scanner plugin for FirebaseRulesAuditor"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            path_lower = file_path.replace('\\', '/').lower()
            is_rules = path_lower.endswith('.rules') or 'database.rules.json' in path_lower
            if not is_rules:
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    def __init__(self):
        self.rules_patterns = [
            {
                "name": "firebase_allow_all_read",
                "pattern": r'allow\s+([^:]*read[^:]*)\s*:\s*if\s*(?:true|\([^\)]*\)\s*|\d+\s*==\s*\d+\s*;?)',
                "severity": "CRITICAL",
                "suggestion": "Rule permits anyone to read all data. Restrict access based on authentication."
            },
            {
                "name": "firebase_allow_all_write",
                "pattern": r'allow\s+([^:]*write[^:]*)\s*:\s*if\s*(?:true|\([^\)]*\)\s*|\d+\s*==\s*\d+\s*;?)',
                "severity": "CRITICAL",
                "suggestion": "Rule permits anyone to write/delete data. Restrict access strictly with auth checks."
            },
            {
                "name": "firebase_missing_auth_check",
                "pattern": r'allow\s+(read|write|create|update|delete).*?[^!]=\s*null', # Simplified check
                "severity": "HIGH",
                "suggestion": "Ensure rules contain proper request.auth != null checks for non-public data."
            },
            {
                "name": "rtdb_allow_all",
                "pattern": r'"\.(read|write)"\s*:\s*(true|"true")', # Realtime DB JSON rules
                "severity": "CRITICAL",
                "suggestion": "Realtime Database is wide open. Use \".read\": \"auth != null\" at minimum."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        is_rules = file_path.endswith('.rules') or 'database.rules.json' in file_path
        if not is_rules:
            return []
            
        for p in self.rules_patterns:
            # Use DOTALL to match across multiple lines and finditer
            for match in re.finditer(p['pattern'], content, re.IGNORECASE | re.DOTALL):
                start_offset = match.start()
                line_idx = content.count('\n', 0, start_offset)
                context_preview = content[max(0, start_offset - 20):min(len(content), match.end() + 20)].replace('\n', ' ')
                
                findings.append({
                    "file": file_path,
                    "line": line_idx + 1,
                    "name": p['name'],
                    "severity": p['severity'],
                    "suggestion": p['suggestion'],
                    "context": context_preview.strip()
                })
        return findings
