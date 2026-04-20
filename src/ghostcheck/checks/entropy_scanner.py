import math
import re

class EntropyScanner:
    def __init__(self, threshold=4.5, min_length=16):
        self.threshold = threshold
        self.min_length = min_length
        # Ignore common base64 or hex characters if they are too regular, 
        # but here we focus on high randomness.
        # We exclude common code patterns like 'import', 'return' to avoid noise
        self.ignore_patterns = [
            re.compile(r'\b(import|export|from|return|class|def|function)\b'),
            re.compile(r'^[a-f0-9]+$'), # Pure hex (often just hashes)
        ]

    def calculate_entropy(self, text):
        if not text:
            return 0
        probabilities = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in probabilities])
        return entropy

    def scan_content(self, file_path, content):
        findings = []
        import os
        filename = os.path.basename(file_path).lower()

        # AC-S7: Skip binary files, lock-files, and massive build data for entropy
        if any(ext in filename for ext in [".lock", ".map", ".min.js", ".bin", ".exe", ".iso"]):
            return []
        if filename in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]:
            return []

        # Look for potential secret strings: 16-128 chars of non-whitespace
        # Exclude common stuff like URI fragments or long class names
        potential_secrets = re.finditer(r'([a-zA-Z0-9+/=_-]{' + str(self.min_length) + r',128})', content)
        
        lines = content.splitlines()
        for match in potential_secrets:
            token = match.group(1)
            
            # Basic noise filtering
            if any(p.search(token) for p in self.ignore_patterns):
                continue
            
            # Filter if it's likely just a long path or URL
            if '/' in token or '\\' in token:
                continue
                
            entropy = self.calculate_entropy(token)
            if entropy > self.threshold:
                # Find line number
                start_offset = match.start()
                line_idx = content.count('\n', 0, start_offset)
                
                findings.append({
                    "file": file_path,
                    "line": line_idx + 1,
                    "name": "high_entropy_secret",
                    "severity": "MEDIUM",
                    "entropy": round(entropy, 2),
                    "context": token,
                    "message": f"High entropy string detected ({round(entropy, 2)}). Likely an undocumented secret.",
                    "suggestion": "Verify if this string is a sensitive token and move it to a secure vault if necessary."
                })
        return findings
