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
                "pattern": r'\b(curl|wget|sh|bash|powershell|exec|rm\s+-rf|git\s+push\s+--force|drop\s+table)\b',
                "severity": "HIGH",
                "suggestion": "Instruction contains dangerous system commands. Attackers use these to pivot or exfiltrate data."
            },
            {
                "name": "human_in_the_loop_bypass",
                "pattern": r'\b(auto-apply|auto-run|no\s+confirmation|without\s+asking|skip\s+review|approve\s+all)\b',
                "severity": "HIGH",
                "suggestion": "Agent is instructed to skip human confirmation for actions. This significantly increases the impact of prompt injection."
            },
            {
                "name": "cross_file_rule_reference",
                "pattern": r'\b(include|reference|import|load)(?::)?\s+["\']?([^"\']+\.(md|mdc|cursorrules|agents|json))["\']?',
                "severity": "MEDIUM",
                "suggestion": "Agent rule references an external file. Ensure the target file is also scanned for malicious instructions."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        # State mapping
        in_code_block = False
        recent_lines = [] # To catch context from headers like "### Forbidden"
        
        negative_keywords = [
            "forbidden", "prohibited", "not allowed", "don't", "dont", "do not", 
            "never", "avoid", "prevent", "rule: no", "strictly against",
            "example:", "sample:", "placeholder", "mock"
        ]

        for i, line in enumerate(lines):
            # Track context
            stripped = line.strip()
            line_lower = line.lower()
            
            # Update recent lines window (last 15 lines to catch distant headers)
            recent_lines.append(line_lower)
            if len(recent_lines) > 15:
                recent_lines.pop(0)

            # Track code blocks
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue
            
            # Context Check
            is_safe = False
            
            # 1. Same-line context
            if any(kw in line_lower for kw in negative_keywords):
                is_safe = True
            
            # 2. Block context (for lists or code blocks)
            if not is_safe:
                is_list_item = bool(re.match(r'^\s*[-*+]\s|^\s*\d+\.\s', line))
                if is_list_item or in_code_block:
                    context_line = ""
                    for prev_line in reversed(recent_lines[:-1]):
                        if prev_line.strip() == "" or prev_line.strip().startswith("```"):
                            continue
                        
                        # Check if intermediate list parent nodes contain the negative keyword
                        if any(kw in prev_line.lower() for kw in negative_keywords):
                            is_safe = True
                            break

                        # Stop when we find a line that is NOT a list item
                        if not re.match(r'^\s*[-*+]\s|^\s*\d+\.\s', prev_line):
                            context_line = prev_line
                            break
                            
                    if not is_safe and context_line and any(kw in context_line.lower() for kw in negative_keywords):
                        is_safe = True
            
            if is_safe:
                continue

            # If it's a code block, only scan if it's a known risky shell/script block
            if in_code_block and not any(x in line_lower for x in ["bash", "sh", "ps1", "powershell"]):
                if not stripped.startswith(("-", "*", ">")):
                    continue
            
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
