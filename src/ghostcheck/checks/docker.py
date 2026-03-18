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

    def check_dockerfile(self, content):
        """Specifically scan Dockerfile content for best practices."""
        findings = []
        lines = content.splitlines()
        
        # Check for missing USER instruction
        if not any(re.match(r"(?i)^USER\s+", line) for line in lines):
            findings.append({
                "file": "Dockerfile",
                "line": 1,
                "rule_name": "Missing USER Instruction",
                "severity": "HIGH",
                "message": "Dockerfile should specify a non-root USER."
            })

        for i, line in enumerate(lines):
            # Check for latest tag in FROM
            if re.match(r"(?i)^FROM\s+.*:latest", line):
                findings.append({
                    "file": "Dockerfile",
                    "line": i + 1,
                    "rule_name": "Latest Tag Usage",
                    "severity": "MEDIUM",
                    "message": "Using 'latest' tag in FROM is risky."
                })
            
            # Check for secrets in ENV
            if re.match(r"(?i)^ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN)=", line):
                findings.append({
                    "file": "Dockerfile",
                    "line": i + 1,
                    "rule_name": "Hardcoded Secret",
                    "severity": "CRITICAL",
                    "message": "Do not hardcode secrets in ENV instructions."
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
                        "message": risk['message']
                    })
        return findings
