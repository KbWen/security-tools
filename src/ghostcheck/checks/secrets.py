import json
import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

def _get_secret_value_part(match_str: str) -> str:
    # If the match contains = or :, take the right part
    if "=" in match_str:
        val = match_str.split("=", 1)[1]
    elif ":" in match_str:
        parts = match_str.split(":", 1)
        if parts[0].strip().lower() in ["http", "https"]:
            val = match_str
        else:
            val = parts[1]
    else:
        val = match_str
    
    # Strip quotes and spaces
    val = val.strip().strip("'\"").strip()
    return val

def _is_placeholder_value(val: str) -> bool:
    val_lower = val.lower().strip()
    
    # 1. Exact or substring match for common placeholder keywords
    placeholders = [
        "your-key-here", "your_key_here", "your-token-here", "your_token_here",
        "insert-key-here", "insert_key_here", "your-api-key", "your_api_key",
        "dummy-value", "dummy_value", "mock-value", "mock_value",
        "placeholder-value", "placeholder_value", "insert-secret-here", "insert_secret_here",
        "your-password", "your_password", "mypassword", "my-password", "my_password",
        "your-secret", "your_secret", "your-client-secret", "your_client_secret",
        "your-hash-key", "your_hash_key"
    ]
    if any(p in val_lower for p in placeholders):
        return True
        
    # 2. Check if the value is a trivial template placeholder (e.g. <your-api-key>, {YOUR_TOKEN})
    if re.match(r'^[\{\<\[\(]?your[_-]?[a-z0-9_-]+[\}\>\]\)]?$', val_lower):
        return True
        
    # 3. Check if the value is mostly repeated dummy chars (e.g., "xxxxxxxx", "00000000", "*******")
    # We strip common non-alphanumeric chars like -, _, *, space
    cleaned = re.sub(r'[^a-zA-Z0-9]', '', val_lower)
    if len(cleaned) >= 4:
        if len(set(cleaned)) == 1 and cleaned[0] in ['x', 'y', 'z', '0', '1', 'a', '*']:
            return True
        # Simple sequential patterns
        if cleaned in ["12345678", "123456789", "1234567890", "abcdefgh", "abcdefghijklmnopqrstuvwxyz"]:
            return True

    return False


class SecretScanner(BaseScannerPlugin):
    def __init__(self, secret_patterns_path):
        with open(secret_patterns_path, 'r', encoding='utf-8') as f:
            self.patterns = json.load(f)
        # Pre-compile patterns for speed
        for p in self.patterns:
            p['_compiled'] = re.compile(p['pattern'])

    @property
    def name(self) -> str:
        return "secret_scanner"

    @property
    def description(self) -> str:
        return "Scans files for hardcoded secrets, API keys, and credentials."

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        allowed_exts = ['.md', '.json', '.txt', '.log', '.yaml', '.yml', '.py', '.js', '.ts', '.sh', '.bash', '.ps1', '.go', '.java', '.kt', '.dart', '.env']
        for file_path in files:
            filename = file_path.replace('\\', '/').split('/')[-1]
            if any(filename.endswith(ext) for ext in allowed_exts) or '.env' in filename:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    findings.extend(self.scan_file(file_path, content))
                except Exception:
                    pass
        return findings

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
            # We must not skip lines entirely just because they are long.
            # If ReDoS is a concern, we should slice the line into chunks, but for now we scan it fully.
            # Skip property-like keys in JS/TS/JSON: confidenceKey: "...", audienceKey: "..."
            # Regex to detect common property key patterns that aren't secrets
            if re.search(r'["\']?[a-zA-Z0-9]+Key["\']?\s*[:=]', line):
                # If it's a generic word + Key, it's likely a config property name, not a secret value
                # We check if it followed by a long high-entropy string later
                pass

            for p in self.patterns:
                match = p['_compiled'].search(line)
                if match:
                    val = match.group(0)
                    
                    # Extract and check the actual secret value part
                    secret_val = _get_secret_value_part(val)
                    if _is_placeholder_value(secret_val):
                        continue
                    
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
