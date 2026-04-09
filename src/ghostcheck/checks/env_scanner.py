import os
import re

class EnvScanner:
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
        lines = content.splitlines()
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, val = line.split('=', 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                
                # Check for debug enabled in production
                if 'DEBUG' in key.upper() and val.upper() in ['TRUE', '1', 'ON']:
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "pattern_name": "Debug Enabled",
                        "severity": "MEDIUM",
                        "value_preview": f"{key}={val}",
                        "suggestion": "Disable DEBUG mode in production environments."
                    })
                
                # Check for wildcard CORS/origins
                if 'CORS' in key.upper() or 'ALLOW_ORIGIN' in key.upper():
                    if val == '*':
                        findings.append({
                            "file": file_path,
                            "line": i + 1,
                            "pattern_name": "Wildcard Origin",
                            "severity": "HIGH",
                            "value_preview": "*",
                            "suggestion": "Specify trusted origins instead of using wildcards (*) for CORS."
                        })

        return findings
