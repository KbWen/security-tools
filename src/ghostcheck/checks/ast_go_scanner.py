import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class GoASTScanner(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "goastsecretscanner"

    @property
    def description(self) -> str:
        return "Scanner plugin for GoASTScanner"

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
    Go AST Scanner (v0.9.0 Foundation).
    Detects hardcoded secrets in Go by matching assignments and validating the string values.
    """
    def __init__(self, secret_patterns):
        self.secret_patterns = secret_patterns

    def scan_file(self, file_path, content):
        findings = []
        if not file_path.lower().endswith('.go'):
            return findings

        # Matches assignments: key := "value", var key = `value`, or struct fields / map keys: Key: "value"
        assignment_pattern = re.compile(rf'(\w+)\s*(?::=|=|:)\s*(["`])([^"`]+)\2')
        
        for match in assignment_pattern.finditer(content):
            var_name = match.group(1)
            var_value = match.group(3)
            
            # Now check var_value against all secret patterns
            for pattern in self.secret_patterns:
                p_regex = pattern.get('pattern')
                if not p_regex:
                    continue
                
                try:
                    match_obj = re.search(p_regex, var_value)
                    if match_obj:
                        val = match_obj.group(0)
                        masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
                        
                        findings.append({
                            "file": file_path,
                            "line": content.count('\n', 0, match.start()) + 1,
                            "severity": pattern.get('severity', 'HIGH'),
                            "name": f"Go Hardcoded {pattern.get('name', 'Secret')}",
                            "message": f"Potential {pattern.get('name', 'Secret')} found in Go variable '{var_name}'.",
                            "value_preview": masked,
                            "context": f"{var_name} := \"{masked}\"",
                            "remediation": f"Move the {pattern.get('name', 'Secret')} to an environment variable or secret manager."
                        })
                        break
                except re.error:
                    continue

        return findings
