import os
import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class EnvScanner(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "envscanner"

    @property
    def description(self) -> str:
        return "Scanner plugin for EnvScanner"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            filename = os.path.basename(file_path).lower()
            # Ensure it is an actual environment configuration file
            if ".env" not in filename:
                continue
            if filename.endswith(".example") or filename.endswith(".sample") or filename.endswith(".template") or filename.endswith(".py") or filename.endswith(".md") or filename.endswith(".json"):
                continue
            if filename != ".env" and not filename.startswith(".env."):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    """
    Specialized scanner for .env files that checks if they are ignored by git.
    Also parses .env variables for potential security misconfigurations.
    """
    
    def __init__(self, root_path, ignore_matcher):
        self.root_path = root_path
        self.ignore_matcher = ignore_matcher

    def scan_file(self, file_path, content):
        findings = []
        filename = os.path.basename(file_path)
        
        # 1. Check if .env is ignored
        if not self.ignore_matcher.is_ignored(file_path):
            findings.append({
                "file": file_path,
                "line": 1,
                "pattern_name": "Unignored Environment File",
                "severity": "CRITICAL",
                "value_preview": f"{filename} is public/not-ignored",
                "suggestion": f"Add {filename} to your .gitignore immediately."
            })

        # 2. Check for suspicious env values
        # Simple multiline .env parser
        env_pattern = re.compile(r'^[ \t]*([a-zA-Z0-9_]+)\s*=\s*(?:(["\'])(.*?)\2|([^\n]*))', re.MULTILINE | re.DOTALL)
        for match in env_pattern.finditer(content):
            key = match.group(1).strip()
            
            if match.group(2): # Quoted value
                val = match.group(3).strip()
            else: # Unquoted value
                val = match.group(4)
                if val:
                    val = val.split('#')[0].strip() # Remove inline comments
                else:
                    val = ""
            
            line_idx = content.count('\n', 0, match.start()) + 1
            
            # Check for debug enabled in production
            if 'DEBUG' in key.upper() and val.upper() in ['TRUE', '1', 'ON']:
                findings.append({
                    "file": file_path,
                    "line": line_idx,
                    "pattern_name": "Debug Enabled",
                    "severity": "MEDIUM",
                    "value_preview": f"{key}={val}",
                    "suggestion": "Disable DEBUG mode in production environments."
                })
            
            # Check for wildcard CORS/origins
            if 'CORS' in key.upper() or 'ALLOW_ORIGIN' in key.upper():
                origins = [o.strip() for o in val.split(',')]
                if '*' in origins:
                    findings.append({
                        "file": file_path,
                        "line": line_idx,
                        "pattern_name": "Wildcard Origin",
                        "severity": "HIGH",
                        "value_preview": "*",
                        "suggestion": "Specify trusted origins instead of using wildcards (*) for CORS."
                    })

        return findings
