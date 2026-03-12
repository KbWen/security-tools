import os
import json
from .checks.hallucination import HallucinationChecker
from .checks.secrets import SecretScanner
from .checks.agent_rules import AgentRulesLinter
from .checks.docker import DockerRiskChecker
from .ignorefile import IgnoreMatcher

class Scanner:
    def __init__(self, root_path, ignore_enabled=True):
        self.root_path = root_path
        self.ignore_enabled = ignore_enabled
        
        # Load data files
        base_dir = os.path.dirname(__file__)
        self.secret_patterns_path = os.path.join(base_dir, 'data', 'secret_patterns.json')
        self.risky_rules_path = os.path.join(base_dir, 'data', 'risky_rules.json')
        
        # Initialize modules
        self.hallucination_checker = HallucinationChecker()
        self.secret_scanner = SecretScanner(self.secret_patterns_path)
        self.rules_linter = AgentRulesLinter(self.risky_rules_path)
        self.docker_checker = DockerRiskChecker()
        
        # AC-14: Ignore Handling
        ignore_file = os.path.join(root_path, '.ghostcheckignore')
        self.ignore_matcher = IgnoreMatcher(ignore_file if ignore_enabled else None)

    def scan_dependencies(self):
        findings = []
        for root, dirs, files in os.walk(self.root_path):
            if self.ignore_enabled:
                dirs[:] = [d for d in dirs if not self.ignore_matcher.is_ignored(os.path.join(root, d))]
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                if file == 'requirements.txt':
                    with open(file_path, 'r', errors='ignore') as f:
                        findings.extend(self.hallucination_checker.check_requirements(f.read()))
                elif file == 'package.json':
                    with open(file_path, 'r', errors='ignore') as f:
                        findings.extend(self.hallucination_checker.check_package_json(f.read()))
        return findings

    def scan_secrets(self):
        findings = []
        for root, dirs, files in os.walk(self.root_path):
            if self.ignore_enabled:
                dirs[:] = [d for d in dirs if not self.ignore_matcher.is_ignored(os.path.join(root, d))]
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                if any(file.endswith(ext) for ext in ['.md', '.json', '.txt', '.log', '.yaml', '.yml', '.py', '.js', '.ts', '.sh', '.bash', '.ps1']):
                    with open(file_path, 'r', errors='ignore') as f:
                        findings.extend(self.secret_scanner.scan_file(file_path, f.read()))
        return findings

    def scan_rules(self):
        findings = []
        for root, dirs, files in os.walk(self.root_path):
            if self.ignore_enabled:
                dirs[:] = [d for d in dirs if not self.ignore_matcher.is_ignored(os.path.join(root, d))]
            if not any(x in root for x in ['.agent', '.agents', '.cursor', '.github/copilot']):
                continue
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                with open(file_path, 'r', errors='ignore') as f:
                    findings.extend(self.rules_linter.scan_file(file_path, f.read()))
        return findings

    def scan_docker(self):
        findings = []
        for root, dirs, files in os.walk(self.root_path):
            if self.ignore_enabled:
                dirs[:] = [d for d in dirs if not self.ignore_matcher.is_ignored(os.path.join(root, d))]
            for file in files:
                if any(x in file for x in ['Dockerfile', 'docker-compose']):
                    file_path = os.path.join(root, file)
                    if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                        continue
                    with open(file_path, 'r', errors='ignore') as f:
                        findings.extend(self.docker_checker.scan_file(file_path, f.read()))
        return findings

    def scan(self):
        # Full scan combines all
        return self.scan_dependencies() + self.scan_secrets() + self.scan_rules() + self.scan_docker()
