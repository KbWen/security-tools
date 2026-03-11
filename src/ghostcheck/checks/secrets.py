import json
import re
import os

class SecretScanner:
    def __init__(self, patterns_path):
        with open(patterns_path, 'r') as f:
            self.patterns = json.load(f)

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        # AC-15: Determine severity modifier based on file type/path
        severity_modifier = self._get_severity_modifier(file_path)
        
        for i, line in enumerate(lines):
            # Skip common false positives
            if any(hint in line.lower() for hint in ["example", "placeholder", "xxx", "your-key-here", "todo"]):
                continue
                
            for p in self.patterns:
                match = re.search(p['pattern'], line)
                if match:
                    original_severity = p['severity']
                    final_severity = self._adjust_severity(original_severity, severity_modifier)
                    
                    # Mask the value for reporting
                    val = match.group(0)
                    masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
                    
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "pattern_name": p['name'],
                        "severity": final_severity,
                        "value_preview": masked
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
