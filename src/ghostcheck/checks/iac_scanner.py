import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class IaCScanner(BaseScannerPlugin):
    def __init__(self):
        # Terraform patterns
        self.tf_patterns = [
            {
                "name": "hardcoded_aws_creds",
                "pattern": r'(access_key|secret_key)\s*=\s*["\'][^"\']+["\']',
                "severity": "CRITICAL",
                "suggestion": "Use environment variables or AWS profiles instead of hardcoding credentials in provider blocks."
            },
            {
                "name": "overly_permissive_security_group",
                "pattern": r'cidr_blocks\s*=\s*\[[^\]]*["\']0\.0\.0\.0/0["\'][^\]]*\]',
                "severity": "HIGH",
                "suggestion": "Restrict CIDR blocks to specific trusted IPs instead of allowing all (0.0.0.0/0)."
            },
            {
                "name": "unencrypted_s3_bucket",
                "pattern": r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*{([^}]*)}', 
                "severity": "LOW",
                "suggestion": "Ensure server_side_encryption_configuration is enabled for S3 buckets."
            },
            {
                "name": "terraform_state_not_ignored",
                "pattern": r'\.tfstate',
                "severity": "CRITICAL",
                "suggestion": "Ensure .tfstate files are added to .gitignore to prevent leaking state data."
            }
        ]
        
        # Kubernetes patterns
        self.k8s_patterns = [
            {
                "name": "privileged_container",
                "pattern": r'privileged:\s*true',
                "severity": "HIGH",
                "suggestion": "Avoid using privileged: true unless absolutely necessary for the container functionality."
            },
            {
                "name": "host_network_enabled",
                "pattern": r'hostNetwork:\s*true',
                "severity": "MEDIUM",
                "suggestion": "Host network sharing can lead to breakout attacks. Use standard networking unless required."
            },
            {
                "name": "hardcoded_secret_in_yaml",
                "pattern": r'kind:\s*Secret.*?stringData:\s*.*?:\s*["\'][^"\']+["\']', # Matches stringData secrets multiline
                "severity": "HIGH",
                "suggestion": "Use External Secrets or sealed secrets instead of committing raw stringData to Git."
            }
        ]

    @property
    def name(self) -> str:
        return "iac_scanner"

    @property
    def description(self) -> str:
        return "Scans Infrastructure as Code files (Terraform, Kubernetes YAML) for misconfigurations."

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            filename = file_path.replace('\\', '/').split('/')[-1]
            if any(filename.endswith(ext) for ext in ['.tf', '.yaml', '.yml']):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    findings.extend(self.scan_file(file_path, content))
                except Exception:
                    pass
        return findings

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        is_tf = file_path.endswith('.tf')
        is_yaml = file_path.endswith('.yaml') or file_path.endswith('.yml')
        
        patterns = []
        if is_tf:
            patterns = self.tf_patterns
        elif is_yaml:
            patterns = self.k8s_patterns
            
        for p in patterns:
            # Use DOTALL to support multiline matching in YAML and TF
            for match in re.finditer(p['pattern'], content, re.IGNORECASE | re.DOTALL):
                # Specific logic for S3 unencrypted bucket check
                if p['name'] == "unencrypted_s3_bucket":
                    block_content = match.group(1)
                    if "server_side_encryption_configuration" in block_content:
                        continue
                        
                start_offset = match.start()
                line_idx = content.count('\n', 0, start_offset)
                context_preview = content[max(0, start_offset):min(len(content), match.end())][:60].replace('\n', ' ')
                
                findings.append({
                    "file": file_path,
                    "line": line_idx + 1,
                    "name": p['name'],
                    "severity": p['severity'],
                    "suggestion": p['suggestion'],
                    "context": context_preview.strip()
                })
        
        # Special check: prevent committing tfstate
        if ".tfstate" in file_path and not file_path.endswith(".gitignore"):
             findings.append({
                "file": file_path,
                "line": 1,
                "name": "terraform_state_file_found",
                "severity": "CRITICAL",
                "suggestion": "Terraform state files contained sensitive data. Do NOT commit them to version control.",
                "context": "File detected: " + os.path.basename(file_path)
            })

        return findings
