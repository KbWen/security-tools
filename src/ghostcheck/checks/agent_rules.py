import json
import re

class AgentRulesLinter:
    def __init__(self, patterns_path):
        with open(patterns_path, 'r', encoding='utf-8') as f:
            self.patterns = json.load(f)
        
        # v0.8.0 advanced patterns
        self.advanced_patterns = [
            {
                "name": "hidden_prompt_injection",
                "pattern": r'[\u200B-\u200D\uFEFF\u202A-\u202E]', # Hidden chars/RTL
                "severity": "CRITICAL",
                "suggestion": "Hidden characters or bidirectional control characters detected. These are often used for prompt injection bypasses."
            },
            {
                "name": "sensitive_path_access",
                "pattern": r'~/\.(ssh|aws|kube|bash_history)|/etc/(passwd|shadow)|/proc/self/environ',
                "severity": "CRITICAL",
                "suggestion": "Agent is instructed to access highly sensitive paths. Verify this is strictly necessary and safe."
            },
            {
                "name": "dangerous_system_command",
                "pattern": r'\b(curl|wget|sh|bash|powershell|exec)\b',
                "severity": "HIGH",
                "suggestion": "Instruction contains dangerous system commands. Attackers use these to pivot or exfiltrate data."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        for i, line in enumerate(lines):
            # Base patterns from JSON
            for p in self.patterns:
                match = re.search(p['pattern'], line)
                if match:
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p.get('name', 'agent_rule_issue'),
                        "severity": p['severity'],
                        "suggestion": p.get('remediation') or p.get('suggestion'),
                        "context": line.strip()
                    })
            
            # v0.8.0 Advanced patterns
            for p in self.advanced_patterns:
                match = re.search(p['pattern'], line, re.IGNORECASE if p['name'] != "hidden_prompt_injection" else 0)
                if match:
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
                    })
        return findings
