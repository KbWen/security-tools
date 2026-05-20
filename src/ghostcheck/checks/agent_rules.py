import json
import re
import os

def _has_keyword(text: str, keyword: str) -> bool:
    keyword_lower = keyword.lower()
    text_lower = text.lower()
    if any(ord(char) > 0x2e80 for char in keyword_lower):
        return keyword_lower in text_lower
        
    # Boundary check for space-delimited/alphanumeric languages
    pattern = r'(?<![a-zA-Z0-9])' + re.escape(keyword_lower) + r'(?![a-zA-Z0-9])'
    return bool(re.search(pattern, text_lower))


class AgentRulesLinter:
    def __init__(self, patterns_path):
        with open(patterns_path, 'r', encoding='utf-8') as f:
            self.patterns = json.load(f)
            
        # Load multilingual keywords from data file
        data_path = os.path.join(os.path.dirname(__file__), "..", "data", "context_keywords.json")
        try:
            with open(data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                negative = data.get("negative_keywords", [])
                example = data.get("example_keywords", [])
                self.safe_keywords = list(set(negative + example))
        except Exception:
            # Fallback to English and Chinese if file is missing
            self.safe_keywords = [
                "forbidden", "prohibited", "not allowed", "don't", "dont", "do not", 
                "never", "avoid", "prevent", "rule: no", "strictly against",
                "example:", "sample:", "placeholder", "mock",
                "避免", "嚴禁", "不可", "請勿", "禁止", "不要", "不應該",
                "例如", "範例", "如："
            ]
        
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
                "pattern": r'(?<!\.)\b(curl|wget|sh|bash|powershell|exec|rm\s+-rf|git\s+push\s+--force|drop\s+table)\b',
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
        
        safe_keywords = getattr(self, "safe_keywords", [])

        for i, line in enumerate(lines):
            # Track context
            stripped = line.strip()
            line_lower = line.lower()
            
            # Update recent lines window (last 100 lines to catch distant headers)
            recent_lines.append(line_lower)
            if len(recent_lines) > 100:
                recent_lines.pop(0)

            # Track code blocks
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue
            
            # Context Check
            is_safe = False
            
            # 1. Same-line context
            if any(_has_keyword(line_lower, kw) for kw in safe_keywords):
                is_safe = True
            
            # 2. Block context (for lists or code blocks)
            if not is_safe:
                is_list_item = bool(re.match(r'^\s*[-*+]\s|^\s*\d+\.\s', line))
                if is_list_item or in_code_block:
                    for prev_line in reversed(recent_lines[:-1]):
                        if prev_line.strip() == "" or prev_line.strip().startswith("```"):
                            continue
                        
                        # Check if intermediate list parent nodes contain the negative keyword
                        if any(_has_keyword(prev_line.lower(), kw) for kw in safe_keywords):
                            is_safe = True
                            break

                        # Stop when we find a major structural element (header)
                        if re.match(r'^#+\s', prev_line):
                            break
            
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
