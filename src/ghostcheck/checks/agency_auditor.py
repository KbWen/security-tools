import re

class AgencyAuditor:
    def __init__(self):
        self.patterns = [
            {
                "name": "excessive_github_token_agency",
                "pattern": r'contents:\s*write|pull-requests:\s*write',
                "severity": "HIGH",
                "suggestion": "Limit GITHUB_TOKEN permissions to contents: read unless write access is strictly required for the AI agent workflow."
            },
            {
                "name": "no_confirmation_instruction",
                "pattern": r'auto-approve|no\s+confirmation|auto-apply|skip\s+review',
                "severity": "MEDIUM",
                "suggestion": "Avoid giving AI agents full autonomy without human-in-the-loop confirmation for critical operations."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        # Only check workflow files or agent rules
        is_workflow = '.github/workflows' in file_path.replace('\\', '/')
        is_rule = any(x in file_path for x in ['.cursorrules', '.mdc', 'AGENTS.md', 'CLAUDE.md'])
        
        if not (is_workflow or is_rule):
            return []

        for i, line in enumerate(lines):
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
