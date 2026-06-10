import ast
import os
import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin


class SilentInstaller(BaseScannerPlugin):

    @property
    def name(self) -> str:
        # Preserve name for configuration compatibility
        return "silentpackageinstalldetector"

    @property
    def description(self) -> str:
        return "Detects dynamic background package installations executed within scripts, rule instructions, or agent tools"

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        for file_path in files:
            ext = os.path.splitext(file_path)[1].lower()
            filename = os.path.basename(file_path).lower()
            
            # Identify target files
            is_target = False
            if ext in ['.py', '.sh', '.ps1', '.bat']:
                is_target = True
            elif filename in ['.cursorrules', '.ghostcheckignore', 'agents.md', 'claude.md'] or ext == '.mdc':
                is_target = True
            elif ext in ['.md', '.json', '.yaml', '.yml'] and ('rule' in filename or 'agent' in filename or 'mcp' in filename):
                is_target = True
                
            if not is_target:
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Fast pre-filtering to optimize CPU
                installers = ['pip', 'npm', 'yarn', 'poetry', 'uv', 'bun', 'cargo', 'gem', 'go get']
                if not any(inst in content.lower() for inst in installers):
                    continue
                
                # Hybrid scanning
                if ext == '.py':
                    try:
                        tree = ast.parse(content, filename=file_path)
                        visitor = PackageInstallVisitor(file_path)
                        visitor.visit(tree)
                        findings.extend(visitor.findings)
                    except Exception:
                        findings.extend(self._scan_text(content, file_path))
                else:
                    findings.extend(self._scan_text(content, file_path))
            except Exception:
                pass
        return findings

    def _scan_text(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. HITL Warning Check (Bypass scanner if human prompts are present anywhere in the file)
        hitl_indicators = ['read -p', 'Read-Host', 'input(', 'readline(', 'confirm(']
        if any(indicator in content for indicator in hitl_indicators):
            return []

        lines = content.split('\n')
        
        # Installer detection regexes
        pip_pattern = re.compile(r'\b(pip[3]?|poetry|uv)\s+(?:pip\s+)?(install|add)\b', re.IGNORECASE)
        npm_pattern = re.compile(r'\b(npm|yarn|bun)\s+(install|add)\b', re.IGNORECASE)
        cargo_pattern = re.compile(r'\b(cargo)\s+install\b', re.IGNORECASE)
        go_pattern = re.compile(r'\b(go)\s+get\b', re.IGNORECASE)

        quiet_flags = ['-y', '--yes', '-q', '--quiet', '--silent', '-s', '--no-input']

        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Skip comments in python/shell
            trimmed = line.strip()
            if trimmed.startswith('#') or trimmed.startswith('//'):
                continue
                
            matched_installer = None
            is_install_cmd = False
            
            # Match installers
            if pip_pattern.search(line_lower):
                matched_installer = 'pip'
                is_install_cmd = True
            elif npm_pattern.search(line_lower):
                matched_installer = 'npm'
                is_install_cmd = True
            elif cargo_pattern.search(line_lower):
                matched_installer = 'cargo'
                is_install_cmd = True
            elif go_pattern.search(line_lower):
                matched_installer = 'go'
                is_install_cmd = True

            if is_install_cmd:
                # 1. Check for silent / auto-yes
                is_silent = False
                for flag in quiet_flags:
                    if flag in line_lower:
                        is_silent = True
                        break
                # Handle grouped short flags e.g. -qy, -s
                if not is_silent:
                    short_flags = re.findall(r'-[a-zA-Z]+', line)
                    for sf in short_flags:
                        if any(char in sf for char in ['q', 'y', 's']):
                            is_silent = True
                            break

                # 2. Check for version pinning
                is_unpinned = False
                parts = line.split()
                
                if matched_installer == 'pip':
                    idx = line_lower.find('install')
                    if idx == -1:
                        idx = line_lower.find('add')
                    after_action = line[idx + 7:].strip()
                    packages = [p for p in after_action.split() if not p.startswith('-')]
                    for p in packages:
                        if p in ['install', 'add', 'requirements.txt', '.'] or p.endswith('.txt'):
                            continue
                        if p.startswith('.') or p.startswith('/') or p.startswith('\\') or '/' in p or '\\' in p:
                            continue
                        if not any(sym in p for sym in ['==', '>=', '<=', '>', '<', '~=']):
                            is_unpinned = True
                            break
                elif matched_installer == 'npm':
                    idx = line_lower.find('install')
                    if idx == -1:
                        idx = line_lower.find('add')
                    after_action = line[idx + 4:].strip()
                    packages = [p for p in after_action.split() if not p.startswith('-')]
                    # If plain 'npm install' with no package args, ignore
                    if len(packages) > 0:
                        for p in packages:
                            if p in ['install', 'add', '.']:
                                continue
                            if p.startswith('.') or p.startswith('/') or p.startswith('\\') or '/' in p or '\\' in p:
                                continue
                            if '@' not in p:
                                is_unpinned = True
                                break
                elif matched_installer == 'cargo':
                    # Cargo install needs --version
                    if 'install' in line_lower and not any(x in line_lower for x in ['--version', '@']):
                        # Make sure there are arguments after install
                        idx = line_lower.find('install')
                        after_action = line[idx + 7:].strip()
                        packages = [p for p in after_action.split() if not p.startswith('-')]
                        if len(packages) > 0:
                            is_unpinned = True
                elif matched_installer == 'go':
                    if 'get' in line_lower and '@' not in line_lower:
                        idx = line_lower.find('get')
                        after_action = line[idx + 3:].strip()
                        packages = [p for p in after_action.split() if not p.startswith('-')]
                        if len(packages) > 0:
                            is_unpinned = True

                if is_silent or is_unpinned:
                    msg = "Dynamic background package installation detected."
                    if is_silent:
                        msg += " The installation runs in silent/auto-yes mode, which is highly dangerous as it bypasses user checks."
                    if is_unpinned:
                        msg += " The package version is not pinned, exposing the system to supply chain dependency hijacking."

                    findings.append({
                        "file": file_path,
                        "line": i,
                        "name": "Silent Package Installation",
                        "severity": "HIGH",
                        "message": msg,
                        "suggestion": "Remove package installations from runtime tool definitions. Dependencies must be pre-installed in docker or python virtual environments and locked in requirements.txt / package.json."
                    })
                
        return findings


class PackageInstallVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.variables = {}
        self.aliases = {}
        self.install_pattern = re.compile(
            r'\b(pip[3]?|npm|yarn|poetry|uv|bun|cargo|gem|go)\b',
            re.IGNORECASE
        )
        self.quiet_flags = ['-q', '--quiet', '--silent', '-s', '--no-input', '-y', '--yes']

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            for alias in node.names:
                full_name = f"{node.module}.{alias.name}"
                if alias.asname:
                    self.aliases[alias.asname] = full_name
                else:
                    self.aliases[alias.name] = full_name
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.variables[target.id] = node.value
        self.generic_visit(node)

    def _resolve_command(self, node) -> tuple[str, list[str]]:
        if isinstance(node, ast.Name):
            if node.id in self.variables:
                return self._resolve_command(self.variables[node.id])
            return ("", [])
        elif isinstance(node, ast.Constant):
            val = str(node.value)
            return (val, val.split())
        elif isinstance(node, ast.List):
            parts = []
            for elt in node.elts:
                _, elt_parts = self._resolve_command(elt)
                parts.extend(elt_parts)
            return (" ".join(parts), parts)
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    val_str, _ = self._resolve_command(value.value)
                    parts.append(val_str or "{}")
            cmd_str = "".join(parts)
            return (cmd_str, cmd_str.split())
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_str, left_parts = self._resolve_command(node.left)
            right_str, right_parts = self._resolve_command(node.right)
            full_str = left_str + right_str
            return (full_str, full_str.split())
        return ("", [])

    def _get_full_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            val_name = self._get_full_name(node.value)
            if val_name:
                resolved_val = self.aliases.get(val_name, val_name)
                return f"{resolved_val}.{node.attr}"
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = self._get_full_name(node.func)
        short_name = node.func.attr if isinstance(node.func, ast.Attribute) else ""

        matched_name = func_name or short_name
        exec_funcs = [
            'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_output', 'subprocess.check_call',
            'os.system', 'os.popen', 'system', 'popen', 'run', 'Popen', 'call', 'check_output', 'check_call'
        ]
        if matched_name in exec_funcs:
            is_valid_exec = True
            if short_name in ['run', 'Popen', 'call', 'check_output', 'check_call'] and func_name and not func_name.startswith('subprocess'):
                is_valid_exec = False
            if short_name in ['system', 'popen'] and func_name and not func_name.startswith('os'):
                is_valid_exec = False
                
            if is_valid_exec and len(node.args) > 0:
                first_arg = node.args[0]
                command_str, command_parts = self._resolve_command(first_arg)

                # Check if it contains installer execution
                if self.install_pattern.search(command_str):
                    # Check if action is install or add
                    is_installation = False
                    if any(act in command_str.lower() for act in ['install', 'add', 'get']):
                        is_installation = True
                    
                    if is_installation:
                        # 1. Check for silent / auto-yes execution
                        is_silent = False
                        for part in command_parts:
                            if any(flag == part for flag in self.quiet_flags):
                                is_silent = True
                                break
                            # handle grouped flags e.g. -qy
                            if part.startswith('-') and not part.startswith('--'):
                                if any(f.replace('-', '') in part for f in ['q', 'y', 's']):
                                    is_silent = True
                                    break
                                    
                        # 2. Check for version pinning
                        is_unpinned = False
                        if 'pip' in command_str or 'uv' in command_str:
                            idx = command_str.lower().find('install')
                            after_install = command_str[idx + 7:].strip()
                            packages = [p for p in after_install.split() if not p.startswith('-')]
                            for p in packages:
                                if p in ['install', 'requirements.txt', '.'] or p.endswith('.txt'):
                                    continue
                                if p.startswith('.') or p.startswith('/') or p.startswith('\\') or '/' in p or '\\' in p:
                                    continue
                                if not any(sym in p for sym in ['==', '>=', '<=', '>', '<', '~=']):
                                    is_unpinned = True
                                    break
                        elif 'npm' in command_str or 'yarn' in command_str:
                            idx = command_str.lower().find('install')
                            if idx == -1:
                                idx = command_str.lower().find('add')
                            after_action = command_str[idx + 4:].strip()
                            packages = [p for p in after_action.split() if not p.startswith('-')]
                            for p in packages:
                                if p not in ['install', 'add', '.']:
                                    if p.startswith('.') or p.startswith('/') or p.startswith('\\') or '/' in p or '\\' in p:
                                        continue
                                    if '@' not in p:
                                        is_unpinned = True
                                        break

                        if is_silent or is_unpinned:
                            severity = "HIGH"
                            msg = "Agent tool contains command to install packages dynamically at runtime."
                            if is_silent:
                                msg += " The installation runs in silent/auto-yes mode, which is highly dangerous as it bypasses user checks."
                            if is_unpinned:
                                msg += " The package version is not pinned, exposing the system to supply chain dependency hijacking."

                            self.findings.append({
                                "file": self.file_path,
                                "line": node.lineno,
                                "name": "Silent Package Installation",
                                "severity": severity,
                                "message": msg,
                                "suggestion": "Remove package installations from runtime tool definitions. Dependencies must be pre-installed in docker or python virtual environments and locked in requirements.txt / package.json."
                            })

        self.generic_visit(node)
