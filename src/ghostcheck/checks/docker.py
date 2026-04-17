import re

class DockerRiskChecker:
    def __init__(self):
        self.risks = [
            {
                "name": "Privileged Container",
                "pattern": r"privileged:\s*true",
                "severity": "HIGH",
                "message": "Privileged containers can bypass many security controls."
            },
            {
                "name": "Root User Execution",
                "pattern": r"(?i)user:\s*['\"]?root['\"]?",
                "severity": "MEDIUM",
                "message": "Running containers as root is a security risk."
            },
            {
                "name": "Insecure Port Mapping",
                "pattern": r"9000:9000|2375:2375", # Portainer/Docker API
                "severity": "HIGH",
                "message": "Exposing sensitive management ports is risky."
            },
            {
                "name": "Latest Tag Usage",
                "pattern": r":latest",
                "severity": "MEDIUM",
                "message": "Using 'latest' tag can lead to non-deterministic builds."
            }
        ]

    def check_dockerfile(self, content, file_path="Dockerfile"):
        """Specifically scan Dockerfile content for best practices."""
        findings = []
        lines = content.splitlines()
        
        # Check for missing USER instruction
        if not any(re.match(r"(?i)^USER\s+", line) for line in lines):
            findings.append({
                "file": file_path,
                "line": 1,
                "rule_name": "Missing USER Instruction",
                "severity": "HIGH",
                "message": "Dockerfile should specify a non-root USER.",
                "suggestion": "Add 'USER <username>' to your Dockerfile to avoid running as root."
            })
        
        # Check for USER root
        for i, line in enumerate(lines):
            if re.match(r"(?i)^USER\s+root\s*$", line.strip()):
                findings.append({
                    "file": file_path,
                    "line": i + 1,
                    "rule_name": "Root User Execution",
                    "severity": "HIGH",
                    "message": "Specify a non-root user for better security.",
                    "suggestion": "Create a dedicated user and use 'USER <name>' instead of root."
                })

        for i, line in enumerate(lines):
            # Check for latest tag in FROM
            if re.match(r"(?i)^FROM\s+.*:latest", line):
                findings.append({
                    "file": file_path,
                    "line": i + 1,
                    "rule_name": "Latest Tag Usage",
                    "severity": "MEDIUM",
                    "message": "Using 'latest' tag in FROM is risky.",
                    "suggestion": "Pin your base image to a specific version or digest (e.g., node:20-alpine)."
                })
            
            # Check for secrets in ENV
            if re.match(r"(?i)^ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN)=", line):
                findings.append({
                    "file": file_path,
                    "line": i + 1,
                    "rule_name": "Hardcoded Secret",
                    "severity": "CRITICAL",
                    "message": "Do not hardcode secrets in ENV instructions.",
                    "suggestion": "Use runtime environment variables, Docker Secrets, or a secret manager."
                })

        return findings

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines):
            for risk in self.risks:
                if re.search(risk['pattern'], line):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "rule_name": risk['name'],
                        "severity": risk['severity'],
                        "message": risk['message'],
                        "suggestion": risk['message'] # Fallback for legacy risks
                    })
        return findings
