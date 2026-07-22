import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class DartASTScanner(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "dartastsecretscanner"

    @property
    def description(self) -> str:
        return "Scanner plugin for DartASTScanner"

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
    Dart/Flutter AST Scanner (v0.9.0 Foundation).
    Detects hardcoded secrets in Dart files by matching assignments and validating values.
    """
    def __init__(self, secret_patterns):
        self.secret_patterns = secret_patterns

    def scan_file(self, file_path, content):
        findings = []
        if not file_path.endswith('.dart'):
            return findings

        # Matches: const key = "value" or String key = "value" or var key = 'value' or key: "value"
        assignment_pattern = re.compile(rf'(?:(?:const|final|String\??|var|late)\s+)*(\w+)\s*[:=]\s*["\']([^"\']+)["\']')
        
        for match in assignment_pattern.finditer(content):
            var_name = match.group(1)
            var_value = match.group(2)
            
            for pattern in self.secret_patterns:
                p_regex = pattern.get('pattern')
                if not p_regex: continue
                try:
                    match_obj = re.search(p_regex, var_value)
                    if match_obj:
                        val = match_obj.group(0)
                        masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
                        
                        findings.append({
                            "file": file_path,
                            "line": content.count('\n', 0, match.start()) + 1,
                            "severity": pattern.get('severity', 'CRITICAL'),
                            "name": f"Dart Hardcoded {pattern.get('name', 'Secret')}",
                            "message": f"Potential {pattern.get('name', 'Secret')} found in Dart variable '{var_name}'.",
                            "value_preview": masked,
                            "context": f"{var_name} = \"{masked}\"",
                            "remediation": "Use flutter_dotenv or compile-time variables (--dart-define)."
                        })
                        break
                except re.error: continue

        # 2. Leaky Debug Prints
        leaky_vars = r'(?:password|api[Kk]ey|token|secret|credential|auth)'
        print_pattern = rf'print\s*\(\s*({leaky_vars})\s*\)'
        for match in re.finditer(print_pattern, content):
            findings.append({
                "file": file_path,
                "line": content.count('\n', 0, match.start()) + 1,
                "severity": "MEDIUM",
                "name": "Dart Leaky Print",
                "message": f"Sensitive variable '{match.group(1)}' is being printed to console.",
                "context": match.group(0),
                "remediation": "Remove print statements in production or use a secure logging library."
            })

        return findings
