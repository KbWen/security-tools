import json
import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class MCPAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "mcpauditor"

    @property
    def description(self) -> str:
        return "Scanner plugin for MCPAuditor"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    def __init__(self):
        self.insecure_bindings = [
            "0.0.0.0", "::", "[::]",
            "0:0:0:0:0:0:0:0", "[0:0:0:0:0:0:0:0]",
            "::ffff:0.0.0.0", "[::ffff:0.0.0.0]"
        ]
        self.patterns = [
            {
                "name": "mcp_insecure_binding",
                "pattern": r'"(host|address|bind|listen)"\s*:\s*"\s*(0\.0\.0\.0|::|\[::\]|0:0:0:0:0:0:0:0|\[0:0:0:0:0:0:0:0\]|::ffff:0\.0\.0\.0|\[::ffff:0\.0\.0\.0\])(:\d+)?\s*"',
                "severity": "CRITICAL",
                "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 or wildcard IPv6 addresses (::) to prevent unauthorized local network access."
            },
            {
                "name": "mcp_custom_registry",
                "pattern": r'--(registry|index-url|extra-index-url)["\']?\s*[=,:]?\s*["\']?https?://(?!npmjs\.org|pypi\.org|python\.org)[^"\'\s]+',
                "severity": "HIGH",
                "suggestion": "MCP server uses a custom package registry. This is a common vector for dependency confusion and rug pull attacks."
            }
        ]

    def _is_insecure_binding(self, val: str) -> bool:
        if not val or not isinstance(val, str):
            return False
        clean_val = val.strip().lower()
        # Handle port suffix like 0.0.0.0:8000 or [::]:8000
        clean_host = clean_val.split(":")[0] if ":" in clean_val and not clean_val.startswith("[") and not clean_val.startswith("::") else clean_val
        if any(b in clean_val for b in self.insecure_bindings):
            return True
        return False

    def _is_env_placeholder(self, val: str) -> bool:
        if not val or not isinstance(val, str):
            return True
        v = val.strip()
        # Environment variables like ${VAR}, $VAR, %VAR%, or common placeholders
        if re.match(r'^\$\{?[A-Za-z0-9_]+\}?$', v):
            return True
        if re.match(r'^%[A-Za-z0-9_]+%$', v):
            return True
        if v.upper() in ["YOUR_API_KEY", "YOUR_TOKEN", "REPLACE_ME", "DUMMY", "TODO", "NONE", "NULL", "CHANGE_ME"]:
            return True
        return False

    def _is_suspicious_description(self, desc: str) -> bool:
        if not desc or not isinstance(desc, str) or len(desc) < 500:
            return False
        # 1. Extremely low character diversity (e.g. repeated dummy/padding characters like 'a'*600)
        if len(set(desc)) < 20:
            return True
        # 2. Continuous unbroken blob without natural whitespace (< 3% spaces)
        if desc.count(' ') / len(desc) < 0.03:
            return True
        # 3. Hidden raw base64 payload block (> 200 consecutive base64 characters)
        if re.search(r'[A-Za-z0-9+/]{200,}={0,2}', desc):
            return True
        # 4. Context stuffing / massive flooding (> 3500 chars)
        if len(desc) > 3500:
            return True
        return False

    def _check_tool_poisoning(self, text: str) -> bool:
        if not text or not isinstance(text, str):
            return False
        # 1. Zero-width character hiding
        if re.search(r'[\u200B-\u200D\uFEFF]', text):
            return True
        # 2. HTML comment prompt injection
        if re.search(r'<!--\s*(?:system|instruction|important|override|ignore|prompt|disregard)\b', text, re.IGNORECASE):
            return True
        # 3. System override tokens or phrases
        if re.search(r'<(?:IMPORTANT|SYSTEM|INSTRUCTION)>', text, re.IGNORECASE):
            return True
        if re.search(r'(?:ignore|disregard)\s+(?:all\s+|any\s+)?(?:prior|previous|above|system)\s+instructions', text, re.IGNORECASE):
            return True
        if re.search(r'you\s+must\s+not\s+reveal\s+this\s+to\s+the\s+user', text, re.IGNORECASE):
            return True
        return False

    def _find_line_number(self, lines: List[str], target_substring: str) -> int:
        if not target_substring:
            return 1
        target_sub = target_substring[:40].strip()
        for i, line in enumerate(lines):
            if target_sub in line:
                return i + 1
        return 1

    def _extract_primary_package(self, cmd_name: str, args: List[Any]) -> str:
        """Extract the primary package argument, safely skipping flags and flag parameters."""
        skip_next = False
        options_with_value = {
            "--python", "-p", "--index", "-i", "--extra-index-url",
            "--registry", "--prefix", "--package", "-c"
        }
        for arg in args:
            if not isinstance(arg, str):
                continue
            if skip_next:
                skip_next = False
                continue
            if arg in options_with_value:
                skip_next = True
                continue
            if arg.startswith("-") or arg.startswith("http://") or arg.startswith("https://"):
                continue
            return arg
        return ""

    def scan_file(self, file_path: str, content: str) -> List[Dict]:
        findings = []
        norm_path = file_path.replace('\\', '/')
        norm_path_lower = norm_path.lower()
        filename = os.path.basename(norm_path).lower()

        is_config = any(x in norm_path_lower for x in ['mcp_config.json', 'mcp.json', '.cursor/mcp.json', 'claude_desktop_config.json']) or filename == 'mcp.json'
        is_server_code = False
        if norm_path_lower.endswith('.py') or norm_path_lower.endswith('.ts') or norm_path_lower.endswith('.js'):
            if 'mcp' in filename or 'mcp' in content.lower():
                is_server_code = True

        if not (is_config or is_server_code):
            return findings

        lines = content.splitlines()

        # --- 1. Audit Server Code Files (.py, .ts, .js) ---
        if is_server_code:
            for i, line in enumerate(lines):
                # 1.1 Insecure SSE host binding in code (0.0.0.0 or :: or 0:0:0:0:0:0:0:0)
                if re.search(r'(?:host|address|bind)\s*[:=]\s*["\'](0\.0\.0\.0|::|\[::\]|0:0:0:0:0:0:0:0|\[0:0:0:0:0:0:0:0\])["\']', line, re.IGNORECASE) or \
                   re.search(r'\.listen\(\s*[^,]+,\s*["\'](0\.0\.0\.0|::|\[::\]|0:0:0:0:0:0:0:0|\[0:0:0:0:0:0:0:0\])["\']', line, re.IGNORECASE):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": "mcp_insecure_binding",
                        "severity": "CRITICAL",
                        "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 or wildcard IPv6 addresses (::) to prevent unauthorized local network access.",
                        "context": line.strip()
                    })

                # 1.2 Tool Poisoning / Confused Deputy in code/docstrings
                if self._check_tool_poisoning(line):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": "mcp_tool_poisoning_injection",
                        "severity": "HIGH",
                        "suggestion": "Potential tool poisoning detected in MCP description/docstring. Review for prompt injection patterns.",
                        "context": line.strip()
                    })

            # Check multiline docstrings for tool poisoning across the whole file
            if not any(f["name"] == "mcp_tool_poisoning_injection" for f in findings):
                if self._check_tool_poisoning(content):
                    findings.append({
                        "file": file_path,
                        "line": 1,
                        "name": "mcp_tool_poisoning_injection",
                        "severity": "HIGH",
                        "suggestion": "Potential tool poisoning detected in MCP description/docstring. Review for prompt injection patterns.",
                        "context": "Multiline docstring containing prompt injection pattern"
                    })

        # --- 2. Audit MCP Config Files (mcp.json, mcp_config.json) ---
        if is_config:
            # 2.1 Try JSON structured DOM parsing first
            parsed_json = None
            try:
                parsed_json = json.loads(content)
            except Exception:
                parsed_json = None

            if isinstance(parsed_json, dict):
                # Determine server configurations
                server_list = []
                if "mcpServers" in parsed_json and isinstance(parsed_json["mcpServers"], dict):
                    server_list = list(parsed_json["mcpServers"].values())
                elif any(k in parsed_json for k in ["command", "args", "host", "address", "bind", "listen", "url", "description", "env"]):
                    server_list = [parsed_json]
                else:
                    server_list = [v for v in parsed_json.values() if isinstance(v, dict)]

                for s_cfg in server_list:
                    if not isinstance(s_cfg, dict):
                        continue

                    # Check env block for hardcoded API keys & host binding
                    env_block = s_cfg.get("env")
                    if isinstance(env_block, dict):
                        for k, v in env_block.items():
                            line_num = self._find_line_number(lines, f'"{k}"')
                            if re.search(r'(API_KEY|TOKEN|SECRET)', k, re.IGNORECASE):
                                if not self._is_env_placeholder(v):
                                    findings.append({
                                        "file": file_path,
                                        "line": line_num,
                                        "name": "mcp_hardcoded_api_key",
                                        "severity": "CRITICAL",
                                        "suggestion": "Do not hardcode API keys in MCP config. Use environment variables or a secret manager.",
                                        "context": f'"{k}": "********"'
                                    })
                            if re.search(r'^(host|address|bind|listen)$', k, re.IGNORECASE):
                                if self._is_insecure_binding(str(v)):
                                    findings.append({
                                        "file": file_path,
                                        "line": line_num,
                                        "name": "mcp_insecure_binding",
                                        "severity": "CRITICAL",
                                        "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 or wildcard IPv6 addresses (::) to prevent unauthorized local network access.",
                                        "context": f'"{k}": "{v}"'
                                    })

                    # Check direct host binding in server object
                    for bind_key in ["host", "address", "bind", "listen"]:
                        if bind_key in s_cfg:
                            b_val = str(s_cfg[bind_key])
                            if self._is_insecure_binding(b_val):
                                line_num = self._find_line_number(lines, f'"{bind_key}"')
                                findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "name": "mcp_insecure_binding",
                                    "severity": "CRITICAL",
                                    "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 or wildcard IPv6 addresses (::) to prevent unauthorized local network access.",
                                    "context": f'"{bind_key}": "{b_val}"'
                                })

                    # Check endpoint url (SSRF / Cloud metadata)
                    url_val = s_cfg.get("url")
                    if isinstance(url_val, str):
                        url_lower = url_val.lower()
                        # Cloud metadata SSRF check
                        if any(meta in url_lower for meta in ["169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254"]):
                            line_num = self._find_line_number(lines, url_val)
                            findings.append({
                                "file": file_path,
                                "line": line_num,
                                "name": "mcp_untrusted_endpoint",
                                "severity": "HIGH",
                                "suggestion": "Detected cloud metadata service endpoint in MCP configuration. This poses a critical SSRF security risk.",
                                "context": f'"url": "{url_val}"'
                            })

                    # Check description
                    desc_val = s_cfg.get("description")
                    if isinstance(desc_val, str):
                        line_num = self._find_line_number(lines, '"description"')
                        if self._check_tool_poisoning(desc_val):
                            findings.append({
                                "file": file_path,
                                "line": line_num,
                                "name": "mcp_tool_poisoning_injection",
                                "severity": "HIGH",
                                "suggestion": "Potential tool poisoning detected in MCP description. Review for prompt injection patterns.",
                                "context": f'"description": "{desc_val[:80]}..."'
                            })
                        elif self._is_suspicious_description(desc_val):
                            findings.append({
                                "file": file_path,
                                "line": line_num,
                                "name": "mcp_suspicious_description_length",
                                "severity": "MEDIUM",
                                "suggestion": "Abnormally long MCP tool/server description. Attackers use large descriptions to hide prompt injection payloads or bypass context windows.",
                                "context": f'"description": "{desc_val[:80]}..."'
                            })

                    # Check command and args
                    raw_cmd = str(s_cfg.get("command", "")).strip()
                    args = s_cfg.get("args", [])
                    if not isinstance(args, list):
                        args = []

                    # Normalize command name (handle .cmd, .exe, path prefixes like /usr/bin/npx)
                    cmd_base = os.path.basename(raw_cmd.replace('\\', '/')).lower()
                    cmd_name = re.sub(r'\.(cmd|exe|bat|sh)$', '', cmd_base)

                    # 2.2 Insecure binding via CLI flags in args (e.g. --host 0.0.0.0 or -h 0.0.0.0)
                    for idx, a in enumerate(args):
                        if isinstance(a, str):
                            if a in ["--host", "--bind", "-b", "--address"] and idx + 1 < len(args):
                                next_val = str(args[idx + 1])
                                if self._is_insecure_binding(next_val):
                                    line_num = self._find_line_number(lines, next_val)
                                    findings.append({
                                        "file": file_path,
                                        "line": line_num,
                                        "name": "mcp_insecure_binding",
                                        "severity": "CRITICAL",
                                        "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 or wildcard IPv6 addresses (::) to prevent unauthorized local network access.",
                                        "context": f'"{a}": "{next_val}"'
                                    })
                            elif any(a.lower().startswith(f"{flag}=") for flag in ["--host", "--bind", "--address"]):
                                val_part = a.split("=", 1)[1]
                                if self._is_insecure_binding(val_part):
                                    line_num = self._find_line_number(lines, a)
                                    findings.append({
                                        "file": file_path,
                                        "line": line_num,
                                        "name": "mcp_insecure_binding",
                                        "severity": "CRITICAL",
                                        "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 or wildcard IPv6 addresses (::) to prevent unauthorized local network access.",
                                        "context": a
                                    })

                    # 2.3 Unpinned stdio package execution (Anthropic guideline)
                    if cmd_name in ["npx", "bunx", "pnpx"]:
                        pkg = self._extract_primary_package(cmd_name, args)
                        if pkg:
                            is_scoped = pkg.startswith("@")
                            parts = pkg.split("@")
                            has_version = False
                            if is_scoped and len(parts) >= 3 and parts[-1]:
                                has_version = True
                            elif not is_scoped and len(parts) >= 2 and parts[-1]:
                                has_version = True
                            if not has_version:
                                line_num = self._find_line_number(lines, f'"{pkg}"')
                                findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "name": "mcp_unpinned_package_exec",
                                    "severity": "HIGH",
                                    "suggestion": f"Pin package version for '{pkg}' in {raw_cmd} (e.g. {pkg}@1.0.0) to prevent dependency confusion and rug pull attacks.",
                                    "context": f'"{raw_cmd}": "{pkg}"'
                                })
                    elif cmd_name in ["uvx", "pipx"]:
                        pkg = self._extract_primary_package(cmd_name, args)
                        if pkg:
                            has_version = ("==" in pkg) or ("@" in pkg) or pkg.startswith(".") or pkg.startswith("/")
                            if not has_version:
                                line_num = self._find_line_number(lines, f'"{pkg}"')
                                findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "name": "mcp_unpinned_package_exec",
                                    "severity": "HIGH",
                                    "suggestion": f"Pin package version for '{pkg}' in {raw_cmd} (e.g. {pkg}==1.0.0) to prevent dependency confusion and rug pull attacks.",
                                    "context": f'"{raw_cmd}": "{pkg}"'
                                })

                    # 2.4 Broad root filesystem mount
                    server_full_str = f"{raw_cmd} {' '.join(str(a) for a in args)}".lower()
                    if any(k in server_full_str for k in ["filesystem", "server-filesystem", "file-system"]):
                        for arg in args:
                            if isinstance(arg, str):
                                norm_arg = arg.strip().replace('\\', '/').rstrip('/').lower()
                                if norm_arg in ["", "/", "~", "/etc", "/root", "/var", "/usr"] or re.match(r'^[a-z]:$', norm_arg):
                                    line_num = self._find_line_number(lines, f'"{arg}"')
                                    findings.append({
                                        "file": file_path,
                                        "line": line_num,
                                        "name": "mcp_broad_root_mount",
                                        "severity": "HIGH",
                                        "suggestion": f"Scope MCP filesystem server access to specific project/workspace directories instead of the root directory '{arg}'.",
                                        "context": f'"args": "{arg}"'
                                    })

            # 2.5 Fallback / line patterns for custom registry & unstructured files
            for i, line in enumerate(lines):
                # Custom registry
                m_reg = re.search(r'--(registry|index-url|extra-index-url)["\']?\s*[=,:]?\s*["\']?https?://(?!npmjs\.org|pypi\.org|python\.org)[^"\'\s]+', line, re.IGNORECASE)
                if m_reg:
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": "mcp_custom_registry",
                        "severity": "HIGH",
                        "suggestion": "MCP server uses a custom package registry. This is a common vector for dependency confusion and rug pull attacks.",
                        "context": line.strip()
                    })

                # If JSON parsing failed, apply regex patterns
                if parsed_json is None:
                    for p in self.patterns:
                        match = re.search(p['pattern'], line, re.IGNORECASE)
                        if match:
                            findings.append({
                                "file": file_path,
                                "line": i + 1,
                                "name": p['name'],
                                "severity": p['severity'],
                                "suggestion": p['suggestion'],
                                "context": line.strip()
                            })

        # Deduplicate findings by (file, line, name, context)
        deduped = []
        seen = set()
        for f in findings:
            key = (f["file"], f["line"], f["name"], f.get("context", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
