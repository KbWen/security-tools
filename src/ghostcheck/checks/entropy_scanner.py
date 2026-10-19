import math
import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

def _is_kebab_case_false_positive(token: str) -> bool:
    if '-' not in token:
        return False
    if not re.match(r'^[a-z0-9-]+$', token): # Enforce lowercase to prevent mixed-case secrets from matching
        return False
    parts = token.split('-')

    # Recognize UI / CSS utility class combinations regardless of length
    css_keywords = {'bg', 'text', 'font', 'border', 'flex', 'grid', 'from', 'to', 'r', 'l', 't', 'b',
                    'gradient', 'indigo', 'purple', 'blue', 'red', 'green', 'yellow', 'gray',
                    'container', 'rounded', 'shadow', 'items', 'justify', 'center', 'relative',
                    'absolute', 'modal', 'button', 'btn', 'card', 'header', 'footer', 'sidebar',
                    'wrapper', 'layout', 'ui', 'box', 'panel', 'icon', 'menu', 'nav', 'link'}
    if len(parts) >= 2 and all((p.lower() in css_keywords) or (p.isdigit() and len(p) <= 4) for p in parts if p):
        return True

    if len(token) > 40:
        return False
    if len(parts) > 5:
        return False
    for part in parts:
        if not part:
            continue
        if part.isalpha():
            if len(part) > 12: # Standard English words/names in CSS are rarely > 12 chars
                return False
        elif part.isdigit():
            if len(part) > 3:
                return False
        else:
            return False
    return True

def _is_path_or_uri_false_positive(token: str, line_str: str) -> bool:
    # 1. Subresource Integrity (SRI) hashes
    if token.startswith(('sha256-', 'sha384-', 'sha512-')):
        return True
    line_lower = line_str.lower()
    if 'integrity=' in line_lower and ('sha256-' in line_str or 'sha384-' in line_str or 'sha512-' in line_str):
        return True

    # 2. Data URIs
    if ';base64,' in line_lower or 'data:image/' in line_lower or 'data:font/' in line_lower or 'data:application/' in line_lower:
        return True

    # 3. URL/file paths containing 2 or more slashes
    if token.count('/') >= 2:
        if '@' in token or '://' in token:
            return False
        if '+' in token or '=' in token:
            return False
        parts = [p for p in token.split('/') if p]
        if len(parts) >= 2:
            if all(re.match(r'^[a-z0-9._-]+$', p) for p in parts):
                return True
            if token.startswith('/') and all(re.match(r'^[a-zA-Z0-9._-]+$', p) for p in parts):
                return True

    return False

class EntropyScanner(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "entropyscanner"

    @property
    def description(self) -> str:
        return "Scanner plugin for EntropyScanner"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            filename = os.path.basename(file_path).lower()
            # AC-S7: Skip binary files, lock-files, and massive build data for entropy
            if any(ext in filename for ext in [".lock", ".map", ".min.js", ".bin", ".exe", ".iso"]):
                continue
            if filename in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]:
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_content(file_path, content))

            except Exception:
                pass
        return findings

    def __init__(self, threshold=4.5, min_length=16):
        self.threshold = threshold
        self.min_length = min_length
        # Ignore common base64 or hex characters if they are too regular, 
        # but here we focus on high randomness.
        # Restrict hex ignore to shorter strings (< 32 chars) and standard hash lengths (32, 40, 64, 128) to avoid false positives.
        self.ignore_patterns = [
            re.compile(r'^[a-fA-F0-9]{1,31}$|^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$'),
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
            
            if _is_kebab_case_false_positive(token):
                continue

            start_offset = match.start()
            line_start = content.rfind('\n', 0, start_offset) + 1
            line_end = content.find('\n', start_offset)
            line_str = content[line_start:line_end if line_end != -1 else len(content)]

            if _is_path_or_uri_false_positive(token, line_str):
                continue
                
            entropy = self.calculate_entropy(token)
            
            # Context Intelligence: Markdown/Text docs have higher natural entropy variance
            # due to URLs, code blocks, or markdown links. Raise threshold.
            effective_threshold = self.threshold
            if any(ext in filename for ext in ['.md', '.mdc', '.txt', '.rst']):
                effective_threshold += 0.5
                
            if entropy > effective_threshold:
                # Find line number
                start_offset = match.start()
                line_idx = content.count('\n', 0, start_offset)
                
                # Mask token for safe reporting in context
                masked_token = token[:4] + "*" * (len(token) - 8) + token[-4:] if len(token) > 8 else "****"
                
                findings.append({
                    "file": file_path,
                    "line": line_idx + 1,
                    "name": "high_entropy_secret",
                    "severity": "MEDIUM",
                    "entropy": round(entropy, 2),
                    "context": masked_token,
                    "_raw_value": token, # Private field for verification only, skipped by reporters
                    "message": f"High entropy string detected ({round(entropy, 2)}). Likely an undocumented secret.",
                    "suggestion": "Verify if this string is a sensitive token and move it to a secure vault if necessary."
                })
        return findings
