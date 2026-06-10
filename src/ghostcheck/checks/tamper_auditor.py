import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class TamperAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "tamperauditor"

    @property
    def description(self) -> str:
        return "Detects attempts to bypass or evade security scanning"

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

    def scan_file(self, file_path: str, content: str) -> List[Dict]:
        findings = []
        
        # 1. Detect excessively long lines hiding at the top
        lines = content.splitlines()
        for i, line in enumerate(lines[:20]):
            if len(line) > 5000:
                findings.append({
                    "file": file_path,
                    "line": i + 1,
                    "name": "Evasion: Long Line Padding",
                    "severity": "HIGH",
                    "message": "File contains excessively long strings at the beginning, often used to bypass scanners.",
                    "suggestion": "Review the file manually for hidden payloads."
                })

        # 2. Detect excessive use of ignores
        ignore_count = content.lower().count("ghostcheck-ignore")
        if ignore_count > 5:
            findings.append({
                "file": file_path,
                "line": 1,
                "name": "Evasion: Excessive Ignores",
                "severity": "MEDIUM",
                "message": f"File uses ghostcheck-ignore {ignore_count} times, which is highly suspicious.",
                "suggestion": "Audit the file's ignores to ensure they are legitimate."
            })

        # 3. Detect invalid ignore syntax hiding in strings/variables
        for i, line in enumerate(lines):
            line_lower = line.lower()
            idx = line_lower.find("ghostcheck-ignore")
            if idx != -1:
                # Check if there is a comment token before it
                prefix = line_lower[:idx]
                if not any(token in prefix for token in ['#', '//', '/*', '<!--', '--', 'rem', '::']):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": "Evasion: Malformed Ignore",
                        "severity": "HIGH",
                        "message": "Found 'ghostcheck-ignore' not inside a proper comment. This might be an attempt to evade detection via payload injection.",
                        "suggestion": "Ensure ignores are properly commented."
                    })

        return findings
