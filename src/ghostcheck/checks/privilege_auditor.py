import re
import os
import json
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class PrivilegeAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "privilegeauditor"

    @property
    def description(self) -> str:
        return "Scanner plugin for PrivilegeAuditor"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        allowed_exts = ['.sh', '.bat', '.py', '.js', '.ts', '.html', '.vue', '.jsx', '.tsx', '.svelte', '.yml', '.yaml', '.json']
        for file_path in files:
            filename = os.path.basename(file_path).lower()
            is_workflow = '.github/workflows' in file_path.replace('\\', '/').lower()
            is_mcp = filename in ['mcp.json', 'mcp_config.json']
            is_code = any(filename.endswith(ext) for ext in allowed_exts)
            if not (is_workflow or is_mcp or is_code):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    def __init__(self):
        # API key regexes
        self.openai_pat = re.compile(r'sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9-_]{40,}')
        self.anthropic_pat = re.compile(r'sk-ant-[a-zA-Z0-9-_]{40,}')
        self.google_pat = re.compile(r'AIzaSy[a-zA-Z0-9_-]{33}')
        
        # Combined API key regex
        self.api_key_regex = re.compile(
            r'(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9-_]{40,}|sk-ant-[a-zA-Z0-9-_]{40,}|AIzaSy[a-zA-Z0-9_-]{33})'
        )

        # Command-line API key pattern
        self.cmd_arg_regex = re.compile(
            r'(?:(?:--|-)(?:api-key|api_key|token|secret|pass|password|k)|(?:API_KEY|TOKEN|SECRET|PASSWORD))\s*[= ]\s*["\']?(sk-|AIzaSy)[a-zA-Z0-9_-]+',
            re.IGNORECASE
        )

    def is_overly_broad_path(self, val):
        if not isinstance(val, str):
            return False
        val_lower = val.lower().strip()
        if val_lower in ["/", "~", "c:\\", "c:/", "c:\\users", "c:/users"]:
            return True
        norm_val = val_lower.replace('\\', '/')
        if norm_val in ["/users", "/home", "/root", "/etc", "/var"]:
            return True
        if ".." in norm_val:
            return True
        parts = [p for p in norm_val.split('/') if p]
        if len(parts) == 2 and parts[0] in ['users', 'home']:
            return True
        if len(parts) == 3 and parts[0].endswith(':') and parts[1] in ['users', 'home']:
            return True
        return False

    def is_elevated_mcp(self, val):
        if not isinstance(val, str):
            return False
        val_lower = val.lower()
        if val_lower in ["sudo", "runas", "su"]:
            return True
        basename = val_lower.split('/')[-1].split('\\')[-1]
        if basename in ["bash", "sh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"]:
            return True
        return False

    def scan_file(self, file_path, content):
        findings = []
        path_lower = file_path.replace('\\', '/').lower()
        filename = os.path.basename(file_path)
        lines = content.splitlines()

        # 1. GitHub Workflows Check
        if '.github/workflows' in path_lower and (filename.endswith('.yml') or filename.endswith('.yaml')):
            has_permissions_block = False
            has_pr_target = False
            has_write_scope = False
            
            pr_target_line = 1
            write_scope_line = 1

            for i, line in enumerate(lines):
                line_strip = line.strip()
                if line_strip.startswith('permissions:'):
                    has_permissions_block = True
                
                if 'pull_request_target' in line:
                    has_pr_target = True
                    pr_target_line = i + 1

                # Check write scopes
                if re.search(r'(actions|checks|deployments|issues|packages|pages|pull-requests|repository-projects|statuses|security-events|contents):\s*write', line, re.IGNORECASE):
                    has_write_scope = True
                    write_scope_line = i + 1
                if re.search(r'permissions:\s*write-all', line, re.IGNORECASE):
                    has_write_scope = True
                    write_scope_line = i + 1

            # GPA-01: github_token_missing_permissions
            if not has_permissions_block:
                findings.append({
                    "file": file_path,
                    "line": 1,
                    "name": "github_token_missing_permissions",
                    "severity": "MEDIUM",
                    "suggestion": "Workflow lacks an explicit 'permissions:' block. Define default permissions as read-all or none to follow the least-privilege principle.",
                    "context": "No permissions block declared in workflow."
                })

            # GPA-02: github_token_excessive_write
            if has_write_scope:
                findings.append({
                    "file": file_path,
                    "line": write_scope_line,
                    "name": "github_token_excessive_write",
                    "severity": "HIGH",
                    "suggestion": "Limit GITHUB_TOKEN write permissions. Avoid granting write scope unless strictly required for automated workflows.",
                    "context": lines[write_scope_line - 1].strip()
                })

            # GPA-03: github_pr_target_write
            if has_pr_target and (not has_permissions_block or has_write_scope):
                findings.append({
                    "file": file_path,
                    "line": pr_target_line,
                    "name": "github_pr_target_write",
                    "severity": "CRITICAL",
                    "suggestion": "Using pull_request_target with write permissions or missing permissions (defaults to write) is highly dangerous. It permits untrusted forks to execute code with write credentials.",
                    "context": lines[pr_target_line - 1].strip()
                })

        # 2. MCP Configuration Check
        is_mcp = any(x in path_lower for x in ['mcp.json', 'mcp_config.json'])
        if is_mcp:
            try:
                data = json.loads(content)
                # Traverse JSON to find GPA-04 and GPA-05
                def traverse(node):
                    if isinstance(node, dict):
                        for k, v in node.items():
                            if self.is_overly_broad_path(v):
                                # Find line number of this value
                                line_num = self._find_val_line(lines, v)
                                findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "name": "mcp_root_mount",
                                    "severity": "CRITICAL",
                                    "suggestion": "MCP server mounts the root or home directory. Limit directory bindings to specific project subfolders.",
                                    "context": f'"{k}": "{v}"'
                                })
                            if self.is_elevated_mcp(v):
                                line_num = self._find_val_line(lines, v)
                                findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "name": "mcp_elevated_execution",
                                    "severity": "HIGH",
                                    "suggestion": "MCP command runs with sudo or invokes shell wrappers. Avoid elevated permissions or shell executions.",
                                    "context": f'"{k}": "{v}"'
                                })
                            traverse(v)
                    elif isinstance(node, list):
                        for item in node:
                            if self.is_overly_broad_path(item):
                                line_num = self._find_val_line(lines, item)
                                findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "name": "mcp_root_mount",
                                    "severity": "CRITICAL",
                                    "suggestion": "MCP server mounts the root or home directory. Limit directory bindings to specific project subfolders.",
                                    "context": f'"{item}"'
                                })
                            if self.is_elevated_mcp(item):
                                line_num = self._find_val_line(lines, item)
                                findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "name": "mcp_elevated_execution",
                                    "severity": "HIGH",
                                    "suggestion": "MCP command runs with sudo or invokes shell wrappers. Avoid elevated permissions or shell executions.",
                                    "context": f'"{item}"'
                                })
                            traverse(item)
                traverse(data)
            except json.JSONDecodeError:
                # If JSON parsing fails, fallback to line scanning
                for i, line in enumerate(lines):
                    if any(x in line for x in ['"sudo"', '"runas"', '"bash"', '"sh"', '"cmd"', '"powershell"']):
                        findings.append({
                            "file": file_path,
                            "line": i + 1,
                            "name": "mcp_elevated_execution",
                            "severity": "HIGH",
                            "suggestion": "MCP command runs with sudo or invokes shell wrappers. Avoid elevated permissions or shell executions.",
                            "context": line.strip()
                        })

        # 3. Code files checks
        allowed_exts = ['.sh', '.bat', '.py', '.js', '.ts', '.html', '.vue', '.jsx', '.tsx', '.svelte']
        is_code = any(filename.endswith(ext) for ext in allowed_exts)
        if is_code:
            # Check client-side indicators for GPA-07
            is_client_side = any(x in path_lower.split('/') for x in ['web', 'frontend', 'client', 'static', 'public']) or \
                             any(filename.endswith(ext) for ext in ['.html', '.vue', '.jsx', '.tsx', '.svelte'])
            
            for i, line in enumerate(lines):
                # GPA-06: api_key_command_arg
                if self.cmd_arg_regex.search(line):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": "api_key_command_arg",
                        "severity": "HIGH",
                        "suggestion": "API key passed as a command-line argument. Pass API keys through environment variables instead.",
                        "context": line.strip()
                    })

                # GPA-07: api_key_hardcoded
                match = self.api_key_regex.search(line)
                if match:
                    raw_key = match.group(1)
                    masked_key = raw_key[:4] + "*" * (len(raw_key) - 8) + raw_key[-4:] if len(raw_key) > 8 else "****"
                    masked_context = line.replace(raw_key, masked_key).strip()
                    
                    if is_client_side:
                        findings.append({
                            "file": file_path,
                            "line": i + 1,
                            "name": "api_key_client_side",
                            "severity": "CRITICAL",
                            "suggestion": "API key hardcoded in client-side code. This key will be exposed to anyone visiting the application. Use backend proxies or serverless functions.",
                            "context": masked_context,
                            "_raw_value": raw_key
                        })
                    else:
                        findings.append({
                            "file": file_path,
                            "line": i + 1,
                            "name": "api_key_hardcoded",
                            "severity": "HIGH",
                            "suggestion": "API key hardcoded in source code. Use environment variables or a secrets manager instead.",
                            "context": masked_context,
                            "_raw_value": raw_key
                        })

        return findings

    def _find_val_line(self, lines, val):
        val_str = str(val)
        for i, line in enumerate(lines):
            if val_str in line:
                return i + 1
        return 1
