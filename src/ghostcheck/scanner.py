import os
import json
from .checks.hallucination import HallucinationChecker
from .checks.secrets import SecretScanner
from .checks.ast_scanner import AstSecretChecker
from .checks.ast_js_scanner import JsAstSecretChecker
from .checks.severity_engine import SeverityEngine
from .checks.env_scanner import EnvScanner
from .checks.agent_rules import AgentRulesLinter
from .checks.docker import DockerRiskChecker
from .checks.iac_scanner import IaCScanner
from .checks.ci_auditor import CIAuditor
from .checks.firebase_rules_auditor import FirebaseRulesAuditor
from .plugins.loader import PluginLoader
from .ignorefile import IgnoreMatcher

class Scanner:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, root_path, ignore_enabled=True, offline=False, config=None, baseline_path=None):
        # Normalize and store absolute path for boundary checks
        self.root_path = os.path.abspath(root_path)
        self.ignore_enabled = ignore_enabled
        self.offline = offline
        self.config = config
        self.baseline_path = baseline_path
        self.baseline_findings = set()
        
        # Load baseline if provided
        if baseline_path and os.path.exists(baseline_path):
            try:
                with open(baseline_path, 'r') as f:
                    data = json.load(f)
                    for fnd in data.get('findings', []):
                        # Create fingerprint: file:line:rule_name
                        fp = f"{fnd.get('file')}:{fnd.get('line')}:{fnd.get('name')}"
                        self.baseline_findings.add(fp)
            except:
                pass

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
        self.js_ast_checker = JsAstSecretChecker(self.raw_secret_patterns)
        self.rules_linter = AgentRulesLinter(self.risky_rules_path)
        self.docker_checker = DockerRiskChecker()
        self.iac_scanner = IaCScanner()
        self.ci_auditor = CIAuditor()
        self.firebase_rules_auditor = FirebaseRulesAuditor()
        self.plugin_loader = PluginLoader()
        self.plugin_loader.load_plugins()
        
        # AC-14: Ignore Handling
        ignore_file = os.path.join(self.root_path, '.ghostcheckignore')
        self.ignore_matcher = IgnoreMatcher(
            ignore_file if ignore_enabled else None,
            base_path=self.root_path
        )

        # v0.5.0 features
        self.severity_engine = SeverityEngine(self.root_path)
        self.env_scanner = EnvScanner(self.root_path, self.ignore_matcher)

    def _is_safe_path(self, file_path):
        """Prevents path traversal by ensuring file is within root_path."""
        abs_path = os.path.abspath(file_path)
        # If targeting a single file, it's safe if it exists. 
        # But if root_path is a directory, verify the file is strictly inside it.
        if os.path.isdir(self.root_path):
             return os.path.commonpath([self.root_path, abs_path]) == self.root_path
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

    def _iter_files(self, limit_files=None):
        if limit_files:
            # Yield specific files for Git Diff Scan
            for f in limit_files:
                if os.path.exists(f) and os.path.isfile(f):
                    yield os.path.dirname(f), [os.path.basename(f)]
            return

        if os.path.isfile(self.root_path):
            yield os.path.dirname(self.root_path), [os.path.basename(self.root_path)]
        else:
            for root, dirs, files in os.walk(self.root_path):
                if self.ignore_enabled:
                    dirs[:] = [d for d in dirs if not self.ignore_matcher.is_ignored(os.path.join(root, d))]
                yield root, files

    def scan_dependencies(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
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

    def scan_secrets(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                # v0.5.0: .env scanning
                if '.env' in file:
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.env_scanner.scan_file(file_path, content))

                allowed_exts = ['.md', '.json', '.txt', '.log', '.yaml', '.yml', '.py', '.js', '.ts', '.sh', '.bash', '.ps1']
                if any(file.endswith(ext) for ext in allowed_exts):
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.secret_scanner.scan_file(file_path, content))
                        if file.endswith('.py'):
                            findings.extend(self.ast_secret_checker.scan_file(file_path, content))
                        elif file.endswith('.js') or file.endswith('.ts'):
                            findings.extend(self.js_ast_checker.scan_file(file_path, content))
                        
                        # Run plugins
                        findings.extend(self.plugin_loader.run_all(file_path, content))
        return findings

    def scan_rules(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            # For rule scanning, we only care about agent-related directories
            # UNLESS a specific file was targeted
            is_file_target = os.path.isfile(self.root_path)
            if not is_file_target and not limit_files and not any(x in root for x in ['.agent', '.agents', '.cursor', '.github/copilot']):
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

    def scan_docker(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                if any(x in file for x in ['Dockerfile', 'docker-compose']) or os.path.isfile(self.root_path):
                    file_path = os.path.join(root, file)
                    if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                        continue
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.docker_checker.scan_file(file_path, content))
        return findings

    def scan_iac(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                # .tf, .yaml, .yml
                if any(file.endswith(ext) for ext in ['.tf', '.yaml', '.yml']):
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.iac_scanner.scan_file(file_path, content))
        return findings

    def scan_ci(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                # .github/workflows, .gitlab-ci, Fastfile, Matchfile
                is_ci = any(x in file_path.replace('\\', '/') for x in ['.github/workflows', '.gitlab-ci', 'Fastfile', 'Matchfile', 'Appfile'])
                # Also check for sensitive mobile config files mentioned in ci_auditor
                is_mobile_cfg = any(k in file for k in ['key.properties', 'GoogleService-Info.plist', 'google-services.json'])
                
                if is_ci or is_mobile_cfg:
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.ci_auditor.scan_file(file_path, content))
        return findings

    def scan_firebase(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                if file.endswith('.rules') or 'database.rules.json' in file:
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.firebase_rules_auditor.scan_file(file_path, content))
        return findings

    def _get_fnd_id(self, fnd):
        """Extracts a stable ID for the finding regardless of which scanner produced it."""
        return fnd.get('pattern_name') or fnd.get('rule_name') or fnd.get('package') or "generic_issue"

    def scan(self, limit_files=None):
        # Full scan combines all
        raw_findings = (
            self.scan_dependencies(limit_files) + 
            self.scan_secrets(limit_files) + 
            self.scan_rules(limit_files) + 
            self.scan_docker(limit_files) +
            self.scan_iac(limit_files) +
            self.scan_ci(limit_files) +
            self.scan_firebase(limit_files)
        )
        
        # v0.6.0: Inline suppression and Baseline filter
        filtered = []
        for fnd in raw_findings:
            # Baseline check
            # Use relative path for stability across environments
            file_path = fnd.get('file', '')
            if not file_path:
                rel_path = ""
            else:
                try:
                    rel_path = os.path.relpath(file_path, self.root_path).replace(os.sep, '/')
                except ValueError:
                    rel_path = file_path.replace(os.sep, '/')
            fnd_id = self._get_fnd_id(fnd)
            line = fnd.get('line', 0)
            
            # Create a stable fingerprint
            fp = f"{rel_path}:{line}:{fnd_id}"
            
            # Also check absolute path fingerprint for compatibility with current create command
            abs_fp = f"{fnd.get('file')}:{line}:{fnd_id}"

            if fp in self.baseline_findings or abs_fp in self.baseline_findings:
                continue
            
            # v0.6.0: Inline comment suppression (regex for ghostcheck-ignore)
            # (Simplification for now: check if the finding has a 'line_content' with ignore tag)
            if "ghostcheck-ignore" in str(fnd.get('context', '')):
                continue

            filtered.append(fnd)

        # v0.5.0: Post-process with Severity Engine
        return self.severity_engine.adjust_findings(filtered)


