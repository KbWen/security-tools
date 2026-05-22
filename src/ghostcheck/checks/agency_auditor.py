import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class AgencyAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "agencyauditor"

    @property
    def description(self) -> str:
        return "Scanner plugin for AgencyAuditor"

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

    def __init__(self):
        self.patterns = [
            {
                "name": "excessive_github_token_agency",
                "pattern": r'contents:\s*write|pull-requests:\s*write',
                "severity": "HIGH",
                "suggestion": "Limit GITHUB_TOKEN permissions to contents: read unless write access is strictly required for the AI agent workflow."
            },
            {
                "name": "agency_excessive_permissions",
                "pattern": r'write-all|write_all|full-access|full_access|sudo|admin|permissions:\s*\*',
                "severity": "CRITICAL",
                "suggestion": "AI agents should operate with least-privilege. Avoid 'write-all' or 'admin' permissions in rule files."
            },
            {
                "name": "agency_destructive_ops",
                "pattern": r'destructive|delete-files|remove-dir|purge|danger',
                "severity": "HIGH",
                "suggestion": "Granting AI agents destructive operations is high risk. Ensure strict human oversight or sandboxing."
            },
            {
                "name": "no_confirmation_instruction",
                "pattern": r'auto-approve|no\s+confirmation|auto-apply|skip\s+review|non-interactive',
                "severity": "MEDIUM",
                "suggestion": "Avoid giving AI agents full autonomy without human-in-the-loop confirmation for critical operations."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        # Only check workflow files or agent rules
        is_workflow = '.github/workflows' in file_path.replace('\\', '/')
        is_rule = any(x in file_path for x in ['.cursorrules', '.mdc', 'AGENTS.md', 'CLAUDE.md', '.agent/rules/'])
        
        if not (is_workflow or is_rule):
            return []

        recent_lines = []
        negative_keywords = [
            "forbidden", "prohibited", "not allowed", "don't", "dont", "do not", 
            "never", "avoid", "prevent", "rule: no", "strictly against",
            "boundary", "restriction", "prohibit"
        ]

        for i, line in enumerate(lines):
            line_lower = line.lower()
            recent_lines.append(line_lower)
            if len(recent_lines) > 15:
                recent_lines.pop(0)

            # Context Check
            is_safe = False
            
            # 1. Same-line context
            if any(kw in line_lower for kw in negative_keywords):
                is_safe = True
            
            # 2. Block context (for lists)
            if not is_safe:
                is_list_item = bool(re.match(r'^\s*[-*+]\s|^\s*\d+\.\s', line))
                if is_list_item:
                    context_line = ""
                    for prev_line in reversed(recent_lines[:-1]):
                        if prev_line.strip() == "" or prev_line.strip().startswith("```"):
                            continue
                        
                        # Check if intermediate list parent nodes contain the negative keyword
                        if any(kw in prev_line.lower() for kw in negative_keywords):
                            is_safe = True
                            break

                        if not re.match(r'^\s*[-*+]\s|^\s*\d+\.\s', prev_line):
                            context_line = prev_line
                            break
                            
                    if not is_safe and context_line and any(kw in context_line.lower() for kw in negative_keywords):
                        is_safe = True
            
            if is_safe:
                continue

            for p in self.patterns:
                if re.search(p['pattern'], line, re.IGNORECASE):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
                    })
        return findings
