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
                "pattern": r"user:\s*['\"]?root['\"]?",
                "severity": "MEDIUM",
                "message": "Running containers as root is a security risk."
            },
            {
                "name": "Insecure Port Mapping",
                "pattern": r"9000:9000|2375:2375", # Portainer/Docker API
                "severity": "HIGH",
                "message": "Exposing sensitive management ports is risky."
            }
        ]

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
