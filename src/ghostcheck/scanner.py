import os
import json
import hashlib
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
from .checks.logic_auditor import LogicAuditor
from .checks.context_auditor import ContextAuditor
from .checks.privilege_auditor import PrivilegeAuditor
from .checks.shadow_ai import ShadowAIDetector
from .scoring import ScoringEngine
from .plugins.loader import PluginLoader
from .ignorefile import IgnoreMatcher
from .presets.manager import PresetManager

class Scanner:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, root_path, ignore_enabled=True, offline=False, config=None, baseline_path=None, version="1.0.0"):
        self.version = version
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
                with open(baseline_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for fnd in data.get('findings', []):
                        # Create fingerprints: legacy (file:line:rule) and robust (file:rule:hash)
                        rule_name = fnd.get('name') or fnd.get('pattern_name') or fnd.get('rule_name') or fnd.get('package') or "generic_issue"
                        fp = f"{fnd.get('file')}:{fnd.get('line')}:{rule_name}"
                        self.baseline_findings.add(fp)
                        
                        rfp = fnd.get('robust_fingerprint')
                        if rfp:
                            self.baseline_findings.add(rfp)
            except (IOError, json.JSONDecodeError, KeyError):
                pass

        self.preset_manager = PresetManager()
        self.active_preset = None
        preset_name = config.get('preset') if config else None
        if preset_name:
            self.active_preset = self.preset_manager.get_preset(preset_name)
        else:
            # Auto-detect if no preset specified
            detected = self.preset_manager.detect_preset(self.root_path)
            if detected != "generic":
                self.active_preset = self.preset_manager.get_preset(detected)

        # Load data files
        base_dir = os.path.dirname(__file__)
        self.cache_dir = os.path.expanduser("~/.ghostcheck/cache")
        self.results_cache_file = os.path.join(self.cache_dir, "results_cache.json")
        self.results_cache = self._load_results_cache()
        self.cache_hits = 0
        self.secret_patterns_path = os.path.join(base_dir, 'data', 'secret_patterns.json')
        self.risky_rules_path = os.path.join(base_dir, 'data', 'risky_rules.json')
        self.owasp_mapping_path = os.path.join(base_dir, 'data', 'owasp_mapping.json')
        
        try:
            with open(self.owasp_mapping_path, 'r', encoding='utf-8') as f:
                self.owasp_mapping = json.load(f)
        except (IOError, json.JSONDecodeError):
            self.owasp_mapping = {}

        try:
            with open(self.secret_patterns_path, 'r', encoding='utf-8') as f:
                self.raw_secret_patterns = json.load(f)
        except (IOError, json.JSONDecodeError):
            self.raw_secret_patterns = []
            
        # 初始化模組
        proxy = self.config.get('proxy') if self.config else None
        ssl_verify = self.config.get('ssl_verify', True) if self.config else True
        timeout = self.config.get('timeout', 10) if self.config else 10
        
        self.hallucination_checker = HallucinationChecker(
            offline=offline, 
            proxy=proxy, 
            ssl_verify=ssl_verify, 
            timeout=timeout
        )
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
        self.vuln_scanner = VulnScanner(
            offline=offline, 
            proxy=proxy, 
            ssl_verify=ssl_verify, 
            timeout=timeout
        )
        self.mobile_auditor = MobileConfigAuditor()
        self.api_linter = APILinter()
        self.secret_validator = SecretValidator(
            enabled=not offline, 
            proxy=proxy, 
            ssl_verify=ssl_verify, 
            timeout=timeout
        )
        self.go_ast_scanner = GoASTScanner(self.raw_secret_patterns)
        self.java_ast_scanner = JavaASTScanner(self.raw_secret_patterns)
        self.dart_ast_scanner = DartASTScanner(self.raw_secret_patterns)
        self.logic_auditor = LogicAuditor()
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
        self.context_auditor = ContextAuditor(config=self.config)
        self.privilege_auditor = PrivilegeAuditor()
        self.shadow_ai_detector = ShadowAIDetector(config=self.config)

    def _is_safe_path(self, file_path):
        """Ensures the path is within project root and handles potential directory traversal."""
        try:
            abs_path = os.path.normpath(os.path.realpath(file_path))
            root_abs = os.path.normpath(self.root_path)
            
            if os.path.isdir(root_abs):
                return os.path.commonpath([root_abs, abs_path]) == root_abs
            return True
        except (ValueError, OSError):
            return False

    def _read_file_safe(self, file_path):
        """Reads file with size limits and path safety. Skips binary files."""
        if not self._is_safe_path(file_path):
            return None
        
        try:
            if os.path.getsize(file_path) > self.MAX_FILE_SIZE:
                return None
                
            # AC-S9: Quick binary check
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:
                    # Likely binary (unless UTF-16, but we primarily target UTF-8 codebases)
                    if not chunk.startswith(b'\xff\xfe') and not chunk.startswith(b'\xfe\xff'):
                        if os.getenv("GHOSTCHECK_DEBUG") == "1":
                            print(f"[DEBUG] Skipping {file_path} as it appears to be binary.")
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

        # Check implementations often contain the regex signatures themselves
        if 'src/ghostcheck/checks/' in file_path:
            # Only exempt pattern-definition matches (e.g. regex strings), NOT actual secrets
            if any(x in fnd_id.lower() for x in ['dangerous_system_command', 'risky_rule', 'hidden_instruction', 'logic_bypass']):
                return True
            # If it's a secret-type finding in a checker file, do NOT exempt — it could be real
            return False
            
        return False

    def _load_results_cache(self) -> dict:
        if os.path.exists(self.results_cache_file):
            try:
                with open(self.results_cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # AC-S3: Use same stable separators for verification
                    if 'integrity' in data:
                        stored_hash = data.pop('integrity')
                        # Include active preset and enabled checks in integrity check to prevent cross-preset cache hits
                        preset_info = self.config.get("preset", "none") if self.config else "none"
                        meta = {"preset": preset_info, "checks": self.config.get("enabled_checks", []) if self.config else []}
                        current_hash = hashlib.sha256((json.dumps(data, sort_keys=True, separators=(',', ':')) + json.dumps(meta, sort_keys=True)).encode()).hexdigest()
                        if stored_hash != current_hash:
                            return {}
                    return data

            except Exception:
                pass
        return {}

    def _save_results_cache(self):
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            # AC-S3: Use stable JSON format for integrity check (no whitespace)
            cache_to_save = self.results_cache.copy()
            if 'integrity' in cache_to_save:
                del cache_to_save['integrity']
            
            # Include preset metadata in integrity hash
            preset_info = self.config.get("preset", "none") if self.config else "none"
            meta = {"preset": preset_info, "checks": self.config.get("enabled_checks", []) if self.config else []}
            
            integrity_hash = hashlib.sha256((json.dumps(cache_to_save, sort_keys=True, separators=(',', ':')) + json.dumps(meta, sort_keys=True)).encode()).hexdigest()
            cache_to_save['integrity'] = integrity_hash
            with open(self.results_cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_to_save, f, separators=(',', ':'))
        except Exception:
            pass

    def _get_file_fingerprint(self, file_path: str) -> str:
        try:
            stat = os.stat(file_path)
            # Use path, mtime, and size for quick fingerprint
            return f"{file_path}|{stat.st_mtime}|{stat.st_size}"
        except OSError:
            return ""

    def _get_finding_hash(self, file_path: str, line: int) -> str:
        """Generates a stable hash based on matching line content."""
        content = self._read_file_safe(file_path)
        if not content or line <= 0:
            return ""
        
        lines = content.splitlines()
        if line > len(lines):
            return ""
            
        # Target line
        target_line = lines[line - 1]
        
        # Normalize: strip whitespace to ignore minor formatting changes
        normalized = target_line.strip()
        # AC-S4: Handle common suppression comments in hash to keep it stable
        normalized = normalized.split('#')[0].strip() # Ignore comments after the line
        
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]



    def _process_single_file(self, file_path):
        """Processes a single file through all relevant scanners."""
        findings = []
        filename = os.path.basename(file_path)
        path_lower = file_path.replace('\\', '/').lower()
        
        # Determine enabled modules for this scan
        if self.active_preset and 'scan_modules' in self.active_preset:
            enabled_modules = self.active_preset['scan_modules']
        else:
            # All modules enabled by default
            enabled_modules = [
                "hallucination", "secrets", "env", "rules", "docker", 
                "iac", "ci_cd", "mobile", "api", "mcp", "supply_chain", "logic", "privilege", "shadow_ai"
            ]
        
        if os.environ.get("GHOSTCHECK_DEBUG") == "1":
            # Extra logs if needed later
            pass


        content = self._read_file_safe(file_path)
        if not content:
            # For vulnerability scanner, it doesn't need content to check manifest files
            if filename in ['requirements.txt', 'package.json']:
                findings.extend(self.vuln_scanner.scan_file(file_path))
            return findings

        # AC-S8: Chaos Protection - Skip generated/minified files with huge unbroken lines
        # that could hang Regex or AST parsers.
        lines = content.split('\n')
        if len(lines) > 0 and (len(content) / len(lines) > 500 or any(len(line) > 10000 for line in lines[:10])):
            if os.getenv("GHOSTCHECK_DEBUG") == "1":
                print(f"[DEBUG] Skipping {filename} as it appears minified or has extremely long lines.")
            return findings

        # 1. Hallucination checks
        if "hallucination" in enabled_modules:
            if filename == 'requirements.txt':
                findings.extend(self.hallucination_checker.check_requirements(content))
            elif filename == 'package.json':
                findings.extend(self.hallucination_checker.check_package_json(content))

        # 2. Secret Scan (General + AST)
        if "secrets" in enabled_modules:
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
            
            if '.env' in filename and "env" in enabled_modules:
                findings.extend(self.env_scanner.scan_file(file_path, content))

        # 3. Agent Rules
        rule_files = ['.cursorrules', 'AGENTS.md', 'CLAUDE.md', 'GEMINI.md']
        is_rule_target = (
            filename.endswith('.md') or 
            filename.endswith('.mdc') or 
            filename in rule_files or 
            (any(x in path_lower for x in ['.agent', '.agents', '.cursor', '.github/copilot']) and not any(filename.endswith(ext) for ext in ['.sh', '.bash', '.ps1', '.cmd', '.py', '.js', '.ts', '.go', '.java']))
        )
        if is_rule_target and "rules" in enabled_modules:
            findings.extend(self.rules_linter.scan_file(file_path, content))

        # 4. Docker / Infrastructure
        if "docker" in enabled_modules:
            if "Dockerfile" in filename:
                findings.extend(self.docker_checker.check_dockerfile(content, file_path))
            elif "docker-compose" in filename:
                findings.extend(self.docker_checker.scan_file(file_path, content))
        if "iac" in enabled_modules and any(filename.endswith(ext) for ext in ['.tf', '.yaml', '.yml']):
            findings.extend(self.iac_scanner.scan_file(file_path, content))
        if "iac" in enabled_modules and (filename.endswith('.rules') or 'database.rules.json' in filename):
            findings.extend(self.firebase_rules_auditor.scan_file(file_path, content))

        # 5. MCP / AI Chain
        if "mcp" in enabled_modules:
            if any(x in path_lower for x in ['mcp.json', 'mcp_config.json']) or filename.endswith('.py') or filename.endswith('.ts'):
                findings.extend(self.mcp_auditor.scan_file(file_path, content))
        
        if "supply_chain" in enabled_modules:
            findings.extend(self.ai_supply_chain.scan_file(file_path, content))
            findings.extend(self.agency_auditor.scan_file(file_path, content))

        # 6. CI/CD & Mobile Config
        is_ci = any(x in path_lower for x in ['.github/workflows', '.gitlab-ci', 'fastfile', 'matchfile', 'appfile'])
        is_mobile_cfg = any(k in filename.lower() for k in ['key.properties', 'googleservice-info.plist', 'google-services.json'])
        if "ci_cd" in enabled_modules and (is_ci or is_mobile_cfg):
            findings.extend(self.ci_auditor.scan_file(file_path, content))
        
        if "mobile" in enabled_modules:
            findings.extend(self.mobile_auditor.scan_file(file_path, content))

        if "privilege" in enabled_modules:
            is_workflow = '.github/workflows' in path_lower
            is_mcp = any(x in path_lower for x in ['mcp.json', 'mcp_config.json'])
            allowed_exts = ['.sh', '.bat', '.py', '.js', '.ts', '.html', '.vue', '.jsx', '.tsx', '.svelte']
            is_code = any(filename.endswith(ext) for ext in allowed_exts)
            if is_workflow or is_mcp or is_code:
                findings.extend(self.privilege_auditor.scan_file(file_path, content))

        if "shadow_ai" in enabled_modules:
            is_manifest = filename in ['package.json', 'requirements.txt', 'pyproject.toml']
            is_vscode = filename == 'extensions.json' and '.vscode' in path_lower
            is_src = any(filename.endswith(ext) for ext in ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.sh', '.bat', '.env']) or filename == '.env'
            if is_manifest or is_vscode or is_src:
                findings.extend(self.shadow_ai_detector.scan_file(file_path, content))

        # 7. Entropy & API
        if "secrets" in enabled_modules:
            findings.extend(self.entropy_scanner.scan_content(file_path, content))
        if "api" in enabled_modules:
            findings.extend(self.api_linter.scan_content(file_path, content))
        
        if "logic" in enabled_modules:
            findings.extend(self.logic_auditor.scan_file(file_path, content))

        # 8. Plugins & Vulnerabilities
        findings.extend(self.plugin_loader.run_all(file_path, content))
        if filename in ['requirements.txt', 'package.json']:
            findings.extend(self.vuln_scanner.scan_file(file_path))

        return findings

    def scan(self, limit_files=None):
        import concurrent.futures
        
        all_files = []
        cached_results = []
        files_to_scan = []

        for root, files in self._iter_files(limit_files):
            for file in files:
                file_path = os.path.join(root, file)
                if self.ignore_enabled and self.ignore_matcher.is_ignored(file_path):
                    continue
                
                # Check cache
                fp = self._get_file_fingerprint(file_path)
                if fp in self.results_cache:
                    self.cache_hits += 1
                    if os.getenv("GHOSTCHECK_DEBUG") == "1":
                        print(f"[DEBUG] Cache hit for {file_path}")
                    cached_results.extend(self.results_cache[fp])
                else:
                    files_to_scan.append(file_path)
                all_files.append(file_path)

        raw_findings = list(cached_results)
        new_scan_cache = {}

        # Optimization: Use max_workers based on CPU count for I/O + Regex heavy tasks
        if files_to_scan:
            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
                future_to_file = {executor.submit(self._process_single_file, f): f for f in files_to_scan}
                for future in concurrent.futures.as_completed(future_to_file):
                    f_path = future_to_file[future]
                    try:
                        result = future.result()
                        if result:
                            raw_findings.extend(result)
                        
                        # Update cache entry for this file
                        fp = self._get_file_fingerprint(f_path)
                        if fp:
                            self.results_cache[fp] = result or []
                    except Exception as e:
                        print(f"Error scanning {f_path}: {e}")
            
            # Save cache after new scans
            self._save_results_cache()
        
        # v0.6.0: Inline suppression and Baseline filter
        filtered = []
        file_content_cache = {}
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
            
            # v1.0.0: Robust Hash-based FP
            content_hash = ""
            if file_path and line > 0:
                content_hash = self._get_finding_hash(file_path, line)
            
            # Stable fingerprints
            # legacy: file:line:rule
            legacy_fp = f"{rel_path}:{line}:{fnd_id}"
            abs_legacy_fp = f"{fnd.get('file')}:{line}:{fnd_id}"
            
            # robust: file:rule:hash
            robust_fp = f"{rel_path}:{fnd_id}:{content_hash}" if content_hash else ""

            if legacy_fp in self.baseline_findings or \
               abs_legacy_fp in self.baseline_findings or \
               (robust_fp and robust_fp in self.baseline_findings):
                continue
            
            # v0.9.0: Self-scan exemption
            if self._is_self_scan_exempt(fnd):
                continue
            
            # Inline suppression
            if "ghostcheck-ignore" in str(fnd.get('context', '')):
                continue

            # Context Intelligence: Filter examples and negative constraints in docs
            if fnd_id != "high_entropy_secret": # Entropy has its own logic
                abs_file_path = fnd.get('file', '')
                if abs_file_path and line > 0 and abs_file_path not in file_content_cache:
                    file_content_cache[abs_file_path] = self._read_file_safe(abs_file_path)
                
                content_for_audit = file_content_cache.get(abs_file_path) if abs_file_path else None
                if content_for_audit and self.context_auditor.is_safe_context(abs_file_path, content_for_audit, line):
                    # Suppress or downgrade. Since we want to eliminate FPs in docs, we suppress.
                    if os.getenv("GHOSTCHECK_DEBUG") == "1":
                        print(f"[DEBUG] ContextAuditor suppressed finding: {fnd_id} at {abs_file_path}:{line}")
                    continue

            # v0.8.0: Secret Validation (if applicable and enabled)
            if 'secret' in fnd_id.lower() or 'token' in fnd_id.lower():
                validation = self.secret_validator.validate(fnd)
                if validation:
                    fnd['validation'] = validation
                    # Optional: Adjust severity if found valid
                    if validation.get('valid') is True:
                        fnd['severity'] = 'CRITICAL'
                        fnd['message'] = (fnd.get('message', '') + " [VERIFIED ACTIVE]").strip()

            # Apply OWASP mapping
            fnd['owasp_llm'] = self.owasp_mapping.get(fnd_id, "N/A")
            fnd['fingerprint'] = legacy_fp
            if robust_fp:
                fnd['robust_fingerprint'] = robust_fp
            
            # AC-H6: Relativize paths for reports
            if 'file' in fnd:
                try:
                    fnd['file'] = os.path.relpath(fnd['file'], self.root_path).replace(os.sep, '/')
                except (ValueError, Exception):
                    fnd['file'] = fnd['file'].replace(os.sep, '/')

            filtered.append(fnd)

        return self.severity_engine.adjust_findings(filtered)


