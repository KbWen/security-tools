import re
import os

class IaCScanner:
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
                "pattern": r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]',
                "severity": "HIGH",
                "suggestion": "Restrict CIDR blocks to specific trusted IPs instead of allowing all (0.0.0.0/0)."
            },
            {
                "name": "unencrypted_s3_bucket",
                "pattern": r'resource\s+"aws_s3_bucket"', # Basic trigger, real deep check would need AST/HCL parser
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
                "pattern": r'kind:\s*Secret.*stringData:\s*[^:]+:\s*["\'][^"\']+["\']', # Matches stringData secrets
                "severity": "HIGH",
                "suggestion": "Use External Secrets or sealed secrets instead of committing raw stringData to Git."
            }
        ]

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
            
        for i, line in enumerate(lines):
            for p in patterns:
                if re.search(p['pattern'], line, re.IGNORECASE if is_tf else 0):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
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
