import os
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

    def _clean_comments(self, content: str, file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        
        # 1. Multi-line comments / docstrings
        # Replace the matches with spaces and newlines of equal length to preserve offsets
        def replacer(m):
            s = m.group(0)
            return ''.join('\n' if c == '\n' else ' ' for c in s)
            
        multiline_patterns = [
            re.compile(r'/\*([\s\S]*?)\*/'),
            re.compile(r'<!--([\s\S]*?)-->'),
            re.compile(r'<\#([\s\S]*?)\#>')
        ]
        if ext in ('.py', '.pyw'):
            multiline_patterns.extend([
                re.compile(r'"""([\s\S]*?)"""'),
                re.compile(r"'''([\s\S]*?)'''")
            ])
            
        for p in multiline_patterns:
            content = p.sub(replacer, content)
            
        # 2. Single-line comments
        # Replace from comment token to end of line with spaces (preserving newline)
        def single_replacer(m):
            return ''.join(' ' for _ in m.group(0))
            
        if ext in ('.py', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg', '.sh', '.bash'):
            content = re.sub(r'#.*', single_replacer, content)
        elif ext in ('.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.kt', '.php', '.cs', '.cpp', '.c', '.h', '.ps1'):
            if ext == '.ps1':
                content = re.sub(r'#.*', single_replacer, content)
            else:
                content = re.compile(r'^\s*#.*', re.MULTILINE).sub(single_replacer, content)
            content = re.sub(r'//.*', single_replacer, content)
            
        return content

    def scan_file(self, file_path, content):
        findings = []
        
        path_lower = file_path.lower().replace('\\', '/')
        # Mobile heuristic expansion: include .dart, .swift, .kt, and directories like /lib/, /android/, /ios/
        is_client_side = any(path_lower.endswith(ext) for ext in ['.jsx', '.tsx', '.vue', '.svelte', '.dart', '.swift', '.kt']) or \
                         any(folder in path_lower for folder in ['/components/', '/views/', '/pages/', '/frontend/', '/lib/', '/android/', '/ios/', '/mobile/'])
                          
        relevant_exts = ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.dart', '.java', '.kt', '.php', '.swift']
        if not any(path_lower.endswith(ext) for ext in relevant_exts):
            return []

        clean_content = self._clean_comments(content, file_path)

        for p in self.logic_patterns:
            if p['name'] == 'potential_logic_bypass' and not is_client_side:
                continue
                
            for match in p['pattern'].finditer(clean_content):
                start_offset = match.start()
                
                line_idx = content.count('\n', 0, start_offset) + 1
                matched_text = match.group(0).strip()
                
                # Get context from the original content
                line_start = content.rfind('\n', 0, start_offset) + 1
                line_end = content.find('\n', start_offset)
                if line_end == -1:
                    line_end = len(content)
                context_snippet = content[line_start:line_end].strip()
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
