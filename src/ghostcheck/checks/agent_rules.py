import json
import re

class AgentRulesLinter:
    def __init__(self, patterns_path):
        with open(patterns_path, 'r') as f:
            self.patterns = json.load(f)

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        for i, line in enumerate(lines):
            for p in self.patterns:
                match = re.search(p['pattern'], line)
                if match:
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "rule_name": p['name'],
                        "severity": p['severity'],
                        "matched_content": match.group(0),
                        "remediation": p['remediation']
                    })
        return findings
