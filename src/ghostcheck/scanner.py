import os
import json
from .checks.hallucination import HallucinationChecker
from .checks.secrets import SecretScanner
from .checks.ast_scanner import AstSecretChecker
from .checks.agent_rules import AgentRulesLinter
from .checks.docker import DockerRiskChecker
from .ignorefile import IgnoreMatcher

class Scanner:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, root_path, ignore_enabled=True, offline=False):
        # Normalize and store absolute path for boundary checks
        self.root_path = os.path.abspath(root_path)
        self.ignore_enabled = ignore_enabled
        self.offline = offline
        
        # Load data files
        base_dir = os.path.dirname(__file__)
        self.secret_patterns_path = os.path.join(base_dir, 'data', 'secret_patterns.json')
        self.risky_rules_path = os.path.join(base_dir, 'data', 'risky_rules.json')
        
        # Load raw patterns for AST scanner
        with open(self.secret_patterns_path, 'r') as f:
            self.raw_secret_patterns = json.load(f)
            
        # Initialize modules
        self.hallucination_checker = HallucinationChecker(offline=offline)
        self.secret_scanner = SecretScanner(self.secret_patterns_path)
        self.ast_secret_checker = AstSecretChecker(self.raw_secret_patterns)
        self.rules_linter = AgentRulesLinter(self.risky_rules_path)
        self.docker_checker = DockerRiskChecker()
        
        # AC-14: Ignore Handling
        ignore_file = os.path.join(self.root_path, '.ghostcheckignore')
        self.ignore_matcher = IgnoreMatcher(ignore_file if ignore_enabled else None)

    def _is_safe_path(self, file_path):
        """Prevents path traversal by ensuring file is within root_path."""
        abs_path = os.path.abspath(file_path)
        # If targeting a single file, it's safe if it exists. 
        # But if root_path is a directory, verify the file is inside it.
        if os.path.isdir(self.root_path):
             return abs_path.startswith(self.root_path)
        return True # Single file target is its own root

    def _read_file_safe(self, file_path):
        """Reads file with size limits and path safety."""
        if not self._is_safe_path(file_path):
            return None
        
        try:
            if os.path.getsize(file_path) > self.MAX_FILE_SIZE:
                return None
            with open(file_path, 'r', errors='ignore') as f:
                return f.read()
        except (IOError, OSError):
            return None

    def _iter_files(self):
        if os.path.isfile(self.root_path):
            yield os.path.dirname(self.root_path), [os.path.basename(self.root_path)]
        else:
            for root, dirs, files in os.walk(self.root_path):
                if self.ignore_enabled:
                    dirs[:] = [d for d in dirs if not self.ignore_matcher.is_ignored(os.path.join(root, d))]
                yield root, files

    def scan_dependencies(self):
        findings = []
        for root, files in self._iter_files():
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                if file == 'requirements.txt':
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.hallucination_checker.check_requirements(content))
                elif file == 'package.json':
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.hallucination_checker.check_package_json(content))
        return findings

    def scan_secrets(self):
        findings = []
        for root, files in self._iter_files():
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                if any(file.endswith(ext) for ext in ['.md', '.json', '.txt', '.log', '.yaml', '.yml', '.py', '.js', '.ts', '.sh', '.bash', '.ps1']):
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.secret_scanner.scan_file(file_path, content))
                        if file.endswith('.py'):
                            findings.extend(self.ast_secret_checker.scan_file(file_path, content))
        return findings

    def scan_rules(self):
        findings = []
        for root, files in self._iter_files():
            # For rule scanning, we only care about agent-related directories
            # UNLESS a specific file was targeted
            is_file_target = os.path.isfile(self.root_path)
            if not is_file_target and not any(x in root for x in ['.agent', '.agents', '.cursor', '.github/copilot']):
                continue
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                # For directories, we check all markdown files in rule folders. 
                # For single files, we check if it looks like a rule file or was explicitly hit.
                if file.endswith('.md') or is_file_target:
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.rules_linter.scan_file(file_path, content))
        return findings

    def scan_docker(self):
        findings = []
        for root, files in self._iter_files():
            for file in files:
                if any(x in file for x in ['Dockerfile', 'docker-compose']) or os.path.isfile(self.root_path):
                    file_path = os.path.join(root, file)
                    if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                        continue
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.docker_checker.scan_file(file_path, content))
        return findings

    def scan(self):
        # Full scan combines all
        return self.scan_dependencies() + self.scan_secrets() + self.scan_rules() + self.scan_docker()
