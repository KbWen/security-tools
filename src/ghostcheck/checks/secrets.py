import json
import re
import os

class SecretScanner:
    def __init__(self, patterns_path):
        with open(patterns_path, 'r', encoding='utf-8') as f:
            self.patterns = json.load(f)
        # Pre-compile patterns for speed
        for p in self.patterns:
            p['_compiled'] = re.compile(p['pattern'])

    def scan_file(self, file_path, content):
        findings = []
        filename = os.path.basename(file_path).lower()
        
        # AC-S6: Skip lock-files for secrets scan as they contain many integrity hashes
        if filename in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]:
            return []

        lines = content.splitlines()
        
        # AC-15: Determine severity modifier based on file type/path
        severity_modifier = self._get_severity_modifier(file_path)
        
        for i, line in enumerate(lines):
            # AC-S8: Chaos Protection - Skip extremely long lines to avoid Regex ReDoS
            if len(line) > 2000:
                continue

            # Skip common false positives
            if any(hint in line.lower() for hint in ["example", "placeholder", "xxx", "your-key-here", "todo"]):
                continue
            
            # Skip property-like keys in JS/TS/JSON: confidenceKey: "...", audienceKey: "..."
            # Regex to detect common property key patterns that aren't secrets
            if re.search(r'["\']?[a-zA-Z0-9]+Key["\']?\s*[:=]', line):
                # If it's a generic word + Key, it's likely a config property name, not a secret value
                # We check if it followed by a long high-entropy string later
                pass

            for p in self.patterns:
                match = p['_compiled'].search(line)
                if match:
                    # Validate match context: if it's a JS property name, skip
                    val = match.group(0)
                    
                    # Heuristic: if the match is the KEY of a JSON/JS object, skip
                    # e.g. "aws_key": "..." -> the "aws_key" string itself might trigger regex 
                    # but we only care about the VALUE.
                    # This is naive but effective for many FPs.
                    if line.strip().startswith(f'"{val}"') or line.strip().startswith(f"'{val}'"):
                        if ":" in line:
                            continue

                    original_severity = p['severity']
                    final_severity = self._adjust_severity(original_severity, severity_modifier)
                    
                    # Mask the value for reporting
                    masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
                    
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "pattern_name": p['name'],
                        "severity": final_severity,
                        "value_preview": masked,
                        "suggestion": p.get('remediation', "Rotate or revoke this secret immediately.")
                    })
        return findings

    def _get_severity_modifier(self, file_path):
        filename = os.path.basename(file_path).lower()
        path_lower = file_path.lower().replace('\\', '/')
        path_parts = path_lower.split('/')
        
        # Priority 1: Downgrade for example/mock/test files or directories
        if any(ext in filename for ext in [".example", ".sample", ".template", "mock", "fixture"]):
            return -1
        if any(p in path_parts for p in ["test", "tests", "spec", "fixtures"]):
            return -1
            
        # Priority 2: Upgrade for AI chat logs / conversations
        if any(kw in path_lower for kw in ["chat", "conversation", "ai-output"]):
            return 1
            
        return 0

    def _adjust_severity(self, severity, modifier):
        levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            current_idx = levels.index(severity)
            new_idx = max(0, min(len(levels) - 1, current_idx + modifier))
            return levels[new_idx]
        except ValueError:
            return severity
