import os
import json
from .checks.hallucination import HallucinationChecker
from .checks.secrets import SecretScanner
from .checks.agent_rules import AgentRulesLinter
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
        
        # AC-14: Ignore Handling
        ignore_file = os.path.join(root_path, '.ghostcheckignore')
        self.ignore_matcher = IgnoreMatcher(ignore_file if ignore_enabled else None)

    def scan(self):
        all_findings = []
        
        for root, dirs, files in os.walk(self.root_path):
            # Exclude ignored directories
            if self.ignore_enabled:
                dirs[:] = [d for d in dirs if not self.ignore_matcher.is_ignored(os.path.join(root, d))]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # AC-14: Check if file is ignored
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                
                # Dependency Checks (AC-2, AC-3)
                if file == 'requirements.txt':
                    with open(file_path, 'r', errors='ignore') as f:
                        all_findings.extend(self.hallucination_checker.check_requirements(f.read()))
                elif file == 'package.json':
                    with open(file_path, 'r', errors='ignore') as f:
                        all_findings.extend(self.hallucination_checker.check_package_json(f.read()))
                
                # Secret Checks (AC-4, AC-15)
                # Filter by executable extensions specified in AC-4
                if any(file.endswith(ext) for ext in ['.md', '.json', '.txt', '.log', '.yaml', '.yml']):
                    with open(file_path, 'r', errors='ignore') as f:
                        all_findings.extend(self.secret_scanner.scan_file(file_path, f.read()))
                
                # Rule Checks (AC-5)
                # Check for agent configs
                if any(x in root for x in ['.agent', '.agents', '.cursor', '.github/copilot']):
                     with open(file_path, 'r', errors='ignore') as f:
                        all_findings.extend(self.rules_linter.scan_file(file_path, f.read()))
                        
        return all_findings
