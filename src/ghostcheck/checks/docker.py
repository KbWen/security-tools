import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class DockerRiskChecker(BaseScannerPlugin):
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
                "pattern": r"(?im)^USER\s+['\"]?(root|0)['\"]?",
                "severity": "MEDIUM",
                "message": "Running containers as root is a security risk."
            },
            {
                "name": "Insecure Port Mapping",
                "pattern": r"(?im)(?:0\.0\.0\.0:)?(?:9000:9000|2375:2375)", # Portainer/Docker API
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

    @property
    def name(self) -> str:
        return "docker_scanner"

    @property
    def description(self) -> str:
        return "Scans Dockerfiles and Docker Compose files for risks"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            filename = file_path.replace('\\', '/').split('/')[-1]
            if "Dockerfile" in filename or "docker-compose" in filename:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    if "Dockerfile" in filename:
                        findings.extend(self.check_dockerfile(content, file_path))
                    elif "docker-compose" in filename:
                        findings.extend(self.scan_file(file_path, content))
                except Exception:
                    pass
        return findings

    def check_dockerfile(self, content, file_path="Dockerfile"):
        """Specifically scan Dockerfile content for best practices."""
        findings = []
        
        # Check for missing USER instruction anywhere
        if not re.search(r"(?im)^\s*USER\s+", content):
            findings.append({
                "file": file_path,
                "line": 1,
                "rule_name": "Missing USER Instruction",
                "severity": "HIGH",
                "message": "Dockerfile should specify a non-root USER.",
                "suggestion": "Add 'USER <username>' to your Dockerfile to avoid running as root."
            })
        
        # Check for USER root
        for match in re.finditer(r"(?im)^\s*USER\s+['\"]?(root|0)['\"]?\s*$", content):
            start_offset = match.start()
            line_idx = content.count('\n', 0, start_offset)
            findings.append({
                "file": file_path,
                "line": line_idx + 1,
                "rule_name": "Root User Execution",
                "severity": "HIGH",
                "message": "Specify a non-root user for better security.",
                "suggestion": "Create a dedicated user and use 'USER <name>' instead of root."
            })

        # Check for latest tag in FROM
        for match in re.finditer(r"(?im)^\s*FROM\s+.*:latest", content):
            start_offset = match.start()
            line_idx = content.count('\n', 0, start_offset)
            findings.append({
                "file": file_path,
                "line": line_idx + 1,
                "rule_name": "Latest Tag Usage",
                "severity": "MEDIUM",
                "message": "Using 'latest' tag in FROM is risky.",
                "suggestion": "Pin your base image to a specific version or digest (e.g., node:20-alpine)."
            })
            
        # Check for secrets in ENV, DOTALL across multiple lines
        for match in re.finditer(r"(?im)^\s*ENV\s+(.*?)(PASSWORD|SECRET|KEY|TOKEN)\s*=", content, re.DOTALL):
            env_block = match.group(0)
            # If there's another Docker instruction in the matched block, it's not a multiline ENV
            if re.search(r'\n[A-Z]+\s+', env_block[1:]): 
                # Re-do search line by line just in case if it spans commands
                pass 
            start_offset = match.start()
            line_idx = content.count('\n', 0, start_offset)
            findings.append({
                "file": file_path,
                "line": line_idx + 1,
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
