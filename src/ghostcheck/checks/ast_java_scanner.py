import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class JavaASTScanner(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "javaastsecretscanner"

    @property
    def description(self) -> str:
        return "Scanner plugin for JavaASTScanner"

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
    Java/Kotlin AST Scanner (v0.9.0 Foundation).
    Detects hardcoded secrets in Java/Kotlin files by matching assignments and validating values.
    """
    def __init__(self, secret_patterns):
        self.secret_patterns = secret_patterns

    def scan_file(self, file_path, content):
        findings = []
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return findings

        # Matches: String key = "value" or val key = "value" or @Value("value")
        # Standard assignments
        assignment_pattern = re.compile(rf'(?:String|val|var)\s+(\w+)\s*=\s*["\']([^"\']+)["\']')
        
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
                            "severity": pattern.get('severity', 'HIGH'),
                            "name": f"Java Hardcoded {pattern.get('name', 'Secret')}",
                            "message": f"Potential {pattern.get('name', 'Secret')} found in Java variable '{var_name}'.",
                            "value_preview": masked,
                            "context": f"{var_name} = \"{masked}\"",
                            "remediation": "Use Spring Boot properties or environment variables."
                        })
                        break
                except re.error: continue

        # Spring @Value
        value_pattern = re.compile(r'@Value\s*\(\s*["\']([^$\{\}][^"\']+)["\']\s*\)')
        for match in value_pattern.finditer(content):
            val = match.group(1)
            masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
            findings.append({
                "file": file_path,
                "line": content.count('\n', 0, match.start()) + 1,
                "severity": "HIGH",
                "name": "Spring @Value Hardcoded Secret",
                "message": "Hardcoded value found in @Value annotation.",
                "value_preview": masked,
                "context": f"@Value(\"{masked}\")",
                "remediation": "Replace hardcoded value with a property placeholder: @Value(\"${some.property}\")"
            })

        return findings
