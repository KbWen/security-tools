import json
import re
import os
import math
import logging
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

_BASE_PLACEHOLDERS = (
    "your-key-here", "your_key_here", "your-token-here", "your_token_here",
    "insert-key-here", "insert_key_here", "your-api-key", "your_api_key", "your-api-key-here", "your_api_key_here",
    "dummy-value", "dummy_value", "mock-value", "mock_value",
    "placeholder-value", "placeholder_value", "insert-secret-here", "insert_secret_here",
    "your-password", "your_password", "your-password-here", "your_password_here", "mypassword", "my-password", "my_password",
    "your-secret", "your_secret", "your-secret-here", "your_secret_here", "your-client-secret", "your_client_secret",
    "your-hash-key", "your_hash_key",
)
_PLACEHOLDER_EXACT_SET = frozenset(
    item
    for p in _BASE_PLACEHOLDERS
    for item in (p, f"<{p}>", f"{{{p}}}")
)
_PLACEHOLDER_TEMPLATE_RE = re.compile(
    r'^[\{\<\[\(]?(your|insert|dummy)[_-]?(key|token|api[_-]?key|secret|password|client[_-]?secret|hash[_-]?key)[_-]?(here|value|token|key)?[\}\>\]\)]?$'
)
_NON_ALNUM_RE = re.compile(r'[^a-zA-Z0-9]')
_JSON_KEY_SUFFIX_RE = re.compile(r'["\']?\s*:')
_ALNUM_DASH_UNDERSCORE_RE = re.compile(r'^[a-zA-Z0-9_-]+$')
_COMMON_KEY_NAMES = frozenset({"aws_key", "aws_secret", "secret", "api_key", "apikey", "token", "password", "pass"})


def _mask_token(token: str) -> str:
    return token[:4] + "*" * (len(token) - 8) + token[-4:] if len(token) > 8 else "****"


def _get_secret_value_part(match_str: str) -> str:
    # Preserve URI schemes (e.g., http://, https://, postgres://) so '=' inside URI credentials is not split off
    if "://" in match_str:
        val = match_str
    else:
        eq_idx = match_str.find("=")
        colon_idx = match_str.find(":")
        if eq_idx != -1 and (colon_idx == -1 or eq_idx < colon_idx):
            val = match_str[eq_idx + 1:]
        elif colon_idx != -1:
            val = match_str[colon_idx + 1:]
        else:
            val = match_str

    # Strip quotes and spaces
    val = val.strip().strip("'\"").strip()
    return val

def _is_placeholder_value(val: str) -> bool:
    val_lower = val.lower().strip()
    
    # 1. Exact or delimited token match for common placeholder keywords
    if val_lower in _PLACEHOLDER_EXACT_SET:
        return True
        
    # 2. Check if the value is a trivial template placeholder (e.g. <your-api-key>, {YOUR_TOKEN}, your-password-here)
    if _PLACEHOLDER_TEMPLATE_RE.match(val_lower):
        return True
        
    # 3. Check if the value is mostly repeated dummy chars (e.g., "xxxxxxxx", "00000000", "*******")
    # We strip common non-alphanumeric chars like -, _, *, space
    cleaned = _NON_ALNUM_RE.sub('', val_lower)
    if len(cleaned) >= 4:
        if len(set(cleaned)) == 1 and cleaned[0] in ['x', 'y', 'z', '0', '1', 'a', '*']:
            return True
        # Simple sequential patterns
        if cleaned in ["12345678", "123456789", "1234567890", "abcdefgh", "abcdefghijklmnopqrstuvwxyz"]:
            return True

    return False

def _calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    return - sum([p * math.log(p) / math.log(2.0) for p in probabilities])

def _is_likely_generic_false_positive(val: str) -> bool:
    val_lower = val.lower().strip()
    
    # 1. Skip filenames and paths (check exact extension suffix)
    known_exts = ['.json', '.txt', '.py', '.env', '.yml', '.yaml', '.ini', '.conf', '.cfg', '.md', '.properties', '.html', '.css', '.js', '.ts', '.tsx', '.jsx', '.toml', '.tf', '.tfvars']
    if any(val_lower.endswith(ext) for ext in known_exts):
        return True
    if '/' in val_lower or '\\' in val_lower or val_lower.startswith('http://') or val_lower.startswith('https://'):
        return True
        
    # 2. Skip common config/header/algorithm names
    common_words = {
        'authorization', 'bearer', 'token', 'apikey', 'secret', 'password', 'none', 'null',
        'undefined', 'true', 'false', 'default', 'test', 'mock', 'dummy', 'symmetric',
        'asymmetric', 'hs256', 'rs256', 'sha256', 'md5', 'bcrypt', 'pbkdf2', 'scrypt',
        'env', 'environment', 'production', 'development', 'staging', 'local', 'localhost',
        'signature', 'algorithm', 'payload', 'header', 'claims', 'subject', 'issuer'
    }
    if val_lower in common_words:
        return True
        
    # 3. Check character variety
    # If the value is purely alphabetic (only letters, no numbers, no symbols) and less than 16 characters
    if val_lower.isalpha() and len(val_lower) < 16:
        return True
        
    # 4. Check Shannon entropy
    entropy = _calculate_entropy(val_lower)
    if entropy < 3.2:
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
        allowed_exts = [
            '.md', '.json', '.txt', '.log', '.yaml', '.yml', '.py', '.js', '.ts',
            '.tsx', '.jsx', '.sh', '.bash', '.ps1', '.go', '.java', '.kt', '.dart',
            '.env', '.toml', '.tf', '.tfvars', '.ini', '.cfg', '.conf', '.properties',
            '.rs', '.rb', '.php', '.cs', '.swift', '.vue', '.svelte', '.htm', '.html'
        ]
        for file_path in files:
            filename = file_path.replace('\\', '/').split('/')[-1]
            if any(filename.endswith(ext) for ext in allowed_exts) or '.env' in filename:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    findings.extend(self.scan_file(file_path, content))
                except Exception as e:
                    logger.debug("SecretScanner error on %s: %s", file_path, e)
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
            line_candidates = []
            seen_line_keys = set()
            specific_raw_values = set()

            for p in self.patterns:
                for match in p['_compiled'].finditer(line):
                    val = match.group(0)

                    # Extract and check the actual secret value part
                    secret_val = _get_secret_value_part(val)
                    if _is_placeholder_value(secret_val):
                        continue

                    if p['name'] == "Generic Secret Key" and _is_likely_generic_false_positive(secret_val):
                        continue

                    # Heuristic: if the match is the KEY of a JSON/JS object, skip
                    # e.g. "aws_key": "..." -> the "aws_key" string itself might trigger regex
                    # but we only care about the VALUE.
                    is_json_key = bool(_JSON_KEY_SUFFIX_RE.match(line, match.end()))
                    if is_json_key:
                        val_lower = val.lower()
                        # Skip if it is a common parameter/config name and not high entropy or starting with secret markers
                        if val_lower in _COMMON_KEY_NAMES:
                            continue
                        if _ALNUM_DASH_UNDERSCORE_RE.match(val) and len(val) < 20 and _calculate_entropy(val) < 4.0:
                            continue

                    line_key = (p['name'], secret_val or val)
                    if line_key in seen_line_keys:
                        continue
                    seen_line_keys.add(line_key)

                    if p['name'] != "Generic Secret Key":
                        specific_raw_values.add(secret_val)

                    line_candidates.append((p, val, secret_val))

            accepted_candidates = [
                (p, val, secret_val)
                for (p, val, secret_val) in line_candidates
                if not (p['name'] == "Generic Secret Key" and secret_val in specific_raw_values)
            ]

            if accepted_candidates:
                # Safely mask all accepted secrets inside the line context to prevent sibling secret leakage
                masked_context = line
                for sv in sorted({c[2] or c[1] for c in accepted_candidates if (c[2] or c[1])}, key=len, reverse=True):
                    masked_context = masked_context.replace(sv, _mask_token(sv))
                masked_context = masked_context.strip()

                for p, val, secret_val in accepted_candidates:
                    final_severity = self._adjust_severity(p['severity'], severity_modifier)
                    masked = _mask_token(val)

                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "pattern_name": p['name'],
                        "severity": final_severity,
                        "value_preview": masked,
                        "context": masked_context,
                        "_raw_value": secret_val, # Private field for verification only, skipped by reporters
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
