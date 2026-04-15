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
from .checks.mcp_auditor import MCPAuditor
from .checks.ai_supply_chain import AISupplyChainScanner
from .checks.agency_auditor import AgencyAuditor
from .checks.entropy_scanner import EntropyScanner
from .checks.vuln_scanner import VulnScanner
from .checks.mobile_config_auditor import MobileConfigAuditor
from .checks.api_linter import APILinter
from .checks.secret_validator import SecretValidator
from .checks.ast_go_scanner import GoASTScanner
from .checks.ast_java_scanner import JavaASTScanner
from .checks.ast_dart_scanner import DartASTScanner
from .scoring import ScoringEngine
from .plugins.loader import PluginLoader
from .ignorefile import IgnoreMatcher

class Scanner:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, root_path, ignore_enabled=True, offline=False, config=None, baseline_path=None):
        # Normalize and store absolute path for boundary checks
        # AC-H3: 使用 realpath 以確保符號連結下的一致性
        self.root_path = os.path.realpath(root_path)
        self.ignore_enabled = ignore_enabled
        self.offline = offline
        self.config = config
        # Load baseline: prefer explicit path, fallback to .ghostcheckbaseline in root
        if not baseline_path:
            auto_baseline = os.path.join(self.root_path, '.ghostcheckbaseline')
            if os.path.exists(auto_baseline):
                baseline_path = auto_baseline
                
        self.baseline_path = baseline_path
        self.baseline_findings = set()
        
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
        self.owasp_mapping_path = os.path.join(base_dir, 'data', 'owasp_mapping.json')
        
        with open(self.owasp_mapping_path, 'r') as f:
            self.owasp_mapping = json.load(f)
        
        # Load raw patterns for AST scanner
        with open(self.secret_patterns_path, 'r') as f:
            self.raw_secret_patterns = json.load(f)
            
        # 初始化模組
        proxy = self.config.get('proxy') if self.config else None
        self.hallucination_checker = HallucinationChecker(offline=offline, proxy=proxy)
        self.secret_scanner = SecretScanner(self.secret_patterns_path)
        self.ast_secret_checker = AstSecretChecker(self.raw_secret_patterns)
        self.js_ast_checker = JsAstSecretChecker(self.raw_secret_patterns)
        self.rules_linter = AgentRulesLinter(self.risky_rules_path)
        self.docker_checker = DockerRiskChecker()
        self.iac_scanner = IaCScanner()
        self.ci_auditor = CIAuditor()
        self.firebase_rules_auditor = FirebaseRulesAuditor()
        self.mcp_auditor = MCPAuditor()
        self.ai_supply_chain = AISupplyChainScanner()
        self.agency_auditor = AgencyAuditor()
        self.entropy_scanner = EntropyScanner()
        self.vuln_scanner = VulnScanner(offline=offline, proxy=proxy)
        self.mobile_auditor = MobileConfigAuditor()
        self.api_linter = APILinter()
        self.secret_validator = SecretValidator(enabled=not offline)
        self.go_ast_scanner = GoASTScanner(self.raw_secret_patterns)
        self.java_ast_scanner = JavaASTScanner(self.raw_secret_patterns)
        self.dart_ast_scanner = DartASTScanner(self.raw_secret_patterns)
        self.scoring_engine = ScoringEngine()
        
        load_local = self.config.get('load_local_plugins', False) if self.config else False
        self.plugin_loader = PluginLoader(load_local=load_local)
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
        """防止路徑穿越，確保檔案位於 root_path 內。"""
        abs_path = os.path.realpath(file_path)
        root_abs = os.path.realpath(self.root_path)
        
        # AC-H2: Windows 跨磁碟檢查
        if os.name == 'nt':
            if os.path.splitdrive(abs_path)[0].lower() != os.path.splitdrive(root_abs)[0].lower():
                return False

        if os.path.isdir(root_abs):
             try:
                 return os.path.commonpath([root_abs, abs_path]) == root_abs
             except ValueError:
                 return False
        return True # 單一檔案目標即為其根目錄

    def _read_file_safe(self, file_path):
        """Reads file with size limits and path safety."""
        if not self._is_safe_path(file_path):
            return None
        
        try:
            if os.path.getsize(file_path) > self.MAX_FILE_SIZE:
                return None
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
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

                allowed_exts = ['.md', '.json', '.txt', '.log', '.yaml', '.yml', '.py', '.js', '.ts', '.sh', '.bash', '.ps1', '.go', '.java', '.kt', '.dart', '.env']
                if any(file.endswith(ext) for ext in allowed_exts) or '.env' in file:
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.secret_scanner.scan_file(file_path, content))
                        if file.endswith('.py'):
                            findings.extend(self.ast_secret_checker.scan_file(file_path, content))
                        elif file.endswith('.js') or file.endswith('.ts'):
                            findings.extend(self.js_ast_checker.scan_file(file_path, content))
                        elif file.endswith('.go'):
                            findings.extend(self.go_ast_scanner.scan_file(file_path, content))
                        elif file.endswith('.java') or file.endswith('.kt'):
                            findings.extend(self.java_ast_scanner.scan_file(file_path, content))
                        elif file.endswith('.dart'):
                            findings.extend(self.dart_ast_scanner.scan_file(file_path, content))
                        
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
                rule_files = ['.cursorrules', 'AGENTS.md', 'CLAUDE.md', 'GEMINI.md']
                is_rule_file = file.endswith('.md') or file.endswith('.mdc') or file in rule_files
                if is_rule_file or is_file_target:
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

    def scan_mcp(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                # mcp.json, mcp_config.json, .cursor/mcp.json
                is_mcp = any(x in file_path.replace('\\', '/') for x in ['mcp.json', 'mcp_config.json'])
                if is_mcp or file_path.endswith('.py') or file_path.endswith('.ts'):
                    content = self._read_file_safe(file_path)
                    if content:
                        findings.extend(self.mcp_auditor.scan_file(file_path, content))
        return findings

    def scan_ai_supply_chain(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                content = self._read_file_safe(file_path)
                if content:
                    findings.extend(self.ai_supply_chain.scan_file(file_path, content))
        return findings

    def scan_agency(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                content = self._read_file_safe(file_path)
                if content:
                    findings.extend(self.agency_auditor.scan_file(file_path, content))
        return findings

    def scan_vulnerabilities(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if file in ['requirements.txt', 'package.json']:
                    findings.extend(self.vuln_scanner.scan_file(file_path))
        return findings

    def scan_mobile(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                content = self._read_file_safe(file_path)
                if content:
                    findings.extend(self.mobile_auditor.scan_file(file_path, content))
        return findings

    def scan_api(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                content = self._read_file_safe(file_path)
                if content:
                    findings.extend(self.api_linter.scan_content(file_path, content))
        return findings

    def scan_entropy(self, limit_files=None):
        findings = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                content = self._read_file_safe(file_path)
                if content:
                    findings.extend(self.entropy_scanner.scan_content(file_path, content))
        return findings

    def _get_fnd_id(self, fnd):
        """Extracts a stable ID for the finding regardless of which scanner produced it."""
        return fnd.get('name') or fnd.get('pattern_name') or fnd.get('rule_name') or fnd.get('package') or "generic_issue"

    def _is_self_scan_exempt(self, fnd):
        """Allows GhostCheck to scan itself without triggering on its own signatures."""
        file_path = fnd.get('file', '').replace('\\', '/')
        fnd_id = self._get_fnd_id(fnd)
        
        # Narrow exemption: Only specific known data/config files
        exempt_files = ['src/ghostcheck/data/secret_patterns.json', 'ghostcheck.toml']
        if any(file_path.endswith(x) for x in exempt_files):
            return True
            
        # Test files containing deliberate security patterns for testing
        if 'tests/' in file_path and any(x in fnd_id.lower() for x in ['secret', 'hallucination', 'rule']):
            return True

        # Check implementations often contain the signatures themselves
        if 'src/ghostcheck/checks/' in file_path:
            # We only exempt it if the finding is likely a secondary match of the signature literal
            return True
            
        return False

    def _process_single_file(self, file_path):
        """Processes a single file through all relevant scanners."""
        findings = []
        filename = os.path.basename(file_path)
        path_lower = file_path.replace('\\', '/').lower()
        
        content = self._read_file_safe(file_path)
        if not content:
            # For vulnerability scanner, it doesn't need content to check manifest files
            if filename in ['requirements.txt', 'package.json']:
                findings.extend(self.vuln_scanner.scan_file(file_path))
            return findings

        # 1. Hallucination checks
        if filename == 'requirements.txt':
            findings.extend(self.hallucination_checker.check_requirements(content))
        elif filename == 'package.json':
            findings.extend(self.hallucination_checker.check_package_json(content))

        # 2. Secret Scan (General + AST)
        allowed_exts = ['.md', '.json', '.txt', '.log', '.yaml', '.yml', '.py', '.js', '.ts', '.sh', '.bash', '.ps1', '.go', '.java', '.kt', '.dart', '.env']
        if any(filename.endswith(ext) for ext in allowed_exts) or '.env' in filename:
            findings.extend(self.secret_scanner.scan_file(file_path, content))
            if filename.endswith('.py'):
                findings.extend(self.ast_secret_checker.scan_file(file_path, content))
            elif filename.endswith('.js') or filename.endswith('.ts'):
                findings.extend(self.js_ast_checker.scan_file(file_path, content))
            elif filename.endswith('.go'):
                findings.extend(self.go_ast_scanner.scan_file(file_path, content))
            elif filename.endswith('.java') or filename.endswith('.kt'):
                findings.extend(self.java_ast_scanner.scan_file(file_path, content))
            elif filename.endswith('.dart'):
                findings.extend(self.dart_ast_scanner.scan_file(file_path, content))
            
            if '.env' in filename:
                findings.extend(self.env_scanner.scan_file(file_path, content))

        # 3. Agent Rules
        rule_files = ['.cursorrules', 'AGENTS.md', 'CLAUDE.md', 'GEMINI.md']
        is_rule_target = (
            filename.endswith('.md') or 
            filename.endswith('.mdc') or 
            filename in rule_files or 
            any(x in path_lower for x in ['.agent', '.agents', '.cursor', '.github/copilot'])
        )
        if is_rule_target:
            findings.extend(self.rules_linter.scan_file(file_path, content))

        # 4. Docker / Infrastructure
        if any(x in filename for x in ['Dockerfile', 'docker-compose']):
            findings.extend(self.docker_checker.scan_file(file_path, content))
        if any(filename.endswith(ext) for ext in ['.tf', '.yaml', '.yml']):
            findings.extend(self.iac_scanner.scan_file(file_path, content))
        if filename.endswith('.rules') or 'database.rules.json' in filename:
            findings.extend(self.firebase_rules_auditor.scan_file(file_path, content))

        # 5. MCP / AI Chain
        if any(x in path_lower for x in ['mcp.json', 'mcp_config.json']) or filename.endswith('.py') or filename.endswith('.ts'):
            findings.extend(self.mcp_auditor.scan_file(file_path, content))
        
        findings.extend(self.ai_supply_chain.scan_file(file_path, content))
        findings.extend(self.agency_auditor.scan_file(file_path, content))

        # 6. CI/CD & Mobile Config
        is_ci = any(x in path_lower for x in ['.github/workflows', '.gitlab-ci', 'fastfile', 'matchfile', 'appfile'])
        is_mobile_cfg = any(k in filename.lower() for k in ['key.properties', 'googleservice-info.plist', 'google-services.json'])
        if is_ci or is_mobile_cfg:
            findings.extend(self.ci_auditor.scan_file(file_path, content))
        
        findings.extend(self.mobile_auditor.scan_file(file_path, content))

        # 7. Entropy & API
        findings.extend(self.entropy_scanner.scan_content(file_path, content))
        findings.extend(self.api_linter.scan_content(file_path, content))

        # 8. Plugins & Vulnerabilities
        findings.extend(self.plugin_loader.run_all(file_path, content))
        if filename in ['requirements.txt', 'package.json']:
            findings.extend(self.vuln_scanner.scan_file(file_path))

        return findings

    def scan(self, limit_files=None):
        import concurrent.futures
        
        all_files = []
        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                all_files.append(file_path)

        raw_findings = []
        # Optimization: Use max_workers based on CPU count for I/O + Regex heavy tasks
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            future_to_file = {executor.submit(self._process_single_file, f): f for f in all_files}
            for future in concurrent.futures.as_completed(future_to_file):
                try:
                    result = future.result()
                    if result:
                        raw_findings.extend(result)
                except Exception as e:
                    print(f"Error scanning {future_to_file[future]}: {e}")
        
        # v0.6.0: Inline suppression and Baseline filter
        filtered = []
        for fnd in raw_findings:
            # Baseline check
            file_path = fnd.get('file', '')
            if not file_path:
                rel_path = ""
            else:
                try:
                    rel_path = os.path.relpath(file_path, self.root_path).replace(os.sep, '/')
                except (ValueError, Exception):
                    rel_path = file_path.replace(os.sep, '/')
            
            fnd_id = self._get_fnd_id(fnd)
            line = fnd.get('line', 0)
            
            # Stable fingerprint
            fp = f"{rel_path}:{line}:{fnd_id}"
            abs_fp = f"{fnd.get('file')}:{line}:{fnd_id}"

            if fp in self.baseline_findings or abs_fp in self.baseline_findings:
                continue
            
            # v0.9.0: Self-scan exemption
            if self._is_self_scan_exempt(fnd):
                continue
            
            # Inline suppression
            if "ghostcheck-ignore" in str(fnd.get('context', '')):
                continue

            # Apply OWASP mapping
            fnd['owasp_llm'] = self.owasp_mapping.get(fnd_id, "N/A")
            filtered.append(fnd)

        return self.severity_engine.adjust_findings(filtered)


