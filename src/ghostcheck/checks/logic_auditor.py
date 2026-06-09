import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class LogicAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "logicauditor"

    @property
    def description(self) -> str:
        return "Scanner plugin for LogicAuditor"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    """
    Scans for potential business logic vulnerabilities, specifically 
    around subscription-bypass, inadequate authorization checks, and 
    hardcoded admin defaults.
    """
    def __init__(self):
        # Compiled patterns designed to prevent ReDoS (limit backtracking length with range)
        # and support multiline scanning via [\s\S]
        self.logic_patterns = [
            {
                "name": "potential_logic_bypass",
                "pattern": re.compile(
                    r'if\s*\(?[\s\S]{0,150}?(is_?premium|is_?pro|is_?subscribed|has_?subscription|vip_?level|is_?admin|debug|is_?dev|is_?test)',
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "suggestion": "Detected sensitive logic check (subscription, admin, or debug mode). Ensure this is reinforced by server-side authorization and NOT easily bypassable via client-side state manipulation."
            },
            {
                "name": "hardcoded_identity_bypass",
                "pattern": re.compile(
                    r'if\s*\(?[\s\S]{0,150}?(user_?id|email|username|\.id\b)[\s\S]{0,100}?(==?|===|!=|!==|in|\.includes|\.startsWith|\.endsWith)\s*[\(\[]?\s*["\']([^"\']+)["\']',
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "suggestion": "Detected hardcoded identity comparison. This is a common pattern for 'backdoor' admin access. Use role-based access control (RBAC) instead."
            },
            {
                "name": "client_side_only_entitlement",
                "pattern": re.compile(
                    r'(localStorage|sessionStorage|cookie|document\.cookie)[\s\S]{0,150}?(plan|tier|sub|license|premium|pro)',
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "suggestion": "Storing or reading entitlement/subscription data directly from client-side storage is high-risk. Users can manipulate these values to bypass paywalls. Use signed JWTs or server-side session checks."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        
        path_lower = file_path.lower().replace('\\', '/')
        # Mobile heuristic expansion: include .dart, .swift, .kt, and directories like /lib/, /android/, /ios/
        is_client_side = any(path_lower.endswith(ext) for ext in ['.jsx', '.tsx', '.vue', '.svelte', '.dart', '.swift', '.kt']) or \
                         any(folder in path_lower for folder in ['/components/', '/views/', '/pages/', '/frontend/', '/lib/', '/android/', '/ios/', '/mobile/'])
                         
        relevant_exts = ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.dart', '.java', '.kt', '.php', '.swift']
        if not any(path_lower.endswith(ext) for ext in relevant_exts):
            return []

        for p in self.logic_patterns:
            if p['name'] == 'potential_logic_bypass' and not is_client_side:
                continue
                
            for match in p['pattern'].finditer(content):
                start_offset = match.start()
                
                # Check if the matched line starts with comment characters
                line_start = content.rfind('\n', 0, start_offset) + 1
                line_end = content.find('\n', start_offset)
                if line_end == -1:
                    line_end = len(content)
                current_line = content[line_start:line_end].strip()
                
                if current_line.startswith(('#', '//', '/*', '*')):
                    continue
                    
                line_idx = content.count('\n', 0, start_offset) + 1
                matched_text = match.group(0).strip()
                # Keep context readable but compact (limit to 100 chars or first line)
                context_snippet = matched_text.splitlines()[0] if matched_text else ""
                if len(context_snippet) > 100:
                    context_snippet = context_snippet[:97] + "..."
                
                findings.append({
                    "file": file_path,
                    "line": line_idx,
                    "name": p['name'],
                    "severity": p['severity'],
                    "suggestion": p['suggestion'],
                    "context": context_snippet
                })
        return findings
