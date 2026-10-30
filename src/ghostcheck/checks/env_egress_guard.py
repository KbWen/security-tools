import ast
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set

from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

# Indicator keywords for Zero-FP protection
PYTHON_AI_INDICATORS = (
    "FastMCP", "mcp.server", "@mcp", "@tool", "BaseTool", "StructuredTool",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "CLAUDE_API_KEY", "OPENROUTER_API_KEY", "langchain", "autogen", "crewai",
    "openai", "anthropic"
)

JS_AI_INDICATORS = (
    "@modelcontextprotocol", "McpServer", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY", "langchain", "autogen", "tool("
)

AI_CONTAINER_WORKLOADS = (
    "openhands", "swe-agent", "autogen", "crewai", "mcp", "langchain",
    "ollama", "vllm", "claude-code", "codex", "ai-agent", "agent-runner"
)

SUBPROCESS_TARGETS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call",
    "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell"
}

OS_TARGETS = {"os.system", "os.popen"}


def _is_line_suppressed(line: str, rule_id: str) -> bool:
    """Checks if a line contains an inline ghostcheck-ignore matching rule_id."""
    m = re.search(r"(?:#|//|/\*)\s*ghostcheck-ignore(?::\s*([^\r\n*#]+))?", line, re.IGNORECASE)
    if not m:
        return False
    targets_str = m.group(1)
    if targets_str is None:
        # Bare ghostcheck-ignore suppresses all rules on that line
        return True

    # Clean up targets: remove any trailing '*/', split by comma, strip, lowercase
    cleaned = targets_str.replace("*/", "").strip()
    if not cleaned:
        return True
    targets = [t.strip().lower() for t in cleaned.split(",") if t.strip()]
    return rule_id.lower() in targets


def _strip_json_comments(text: str) -> str:
    """Safely strip single-line and multi-line comments from JSON content."""
    result = []
    in_string = False
    escape = False
    in_single_comment = False
    in_multi_comment = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_single_comment:
            if ch == "\n":
                in_single_comment = False
                result.append(ch)
            i += 1
            continue
        if in_multi_comment:
            if ch == "*" and nxt == "/":
                in_multi_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            result.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_single_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_multi_comment = True
            i += 2
            continue
        result.append(ch)
        i += 1
    return "".join(result)


def _extract_paren_content(text: str, start_paren_idx: int) -> str:
    """Extracts balanced content between '(' and ')' starting at start_paren_idx."""
    depth = 0
    in_single_quote = False
    in_double_quote = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False
    escape = False

    i = start_paren_idx
    n = len(text)
    arg_start = start_paren_idx + 1

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_single_quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_single_quote = False
            i += 1
            continue

        if in_double_quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_double_quote = False
            i += 1
            continue

        if in_backtick:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "`":
                in_backtick = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == "'":
            in_single_quote = True
            i += 1
            continue
        if ch == '"':
            in_double_quote = True
            i += 1
            continue
        if ch == "`":
            in_backtick = True
            i += 1
            continue

        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[arg_start:i]

        i += 1

    return text[arg_start:]


def _get_first_js_argument(args_str: str) -> str:
    """Extracts the first argument up to top-level comma in JS argument list."""
    depth = 0
    in_single_quote = False
    in_double_quote = False
    in_backtick = False
    escape = False

    for i, ch in enumerate(args_str):
        if in_single_quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_single_quote = False
            continue
        if in_double_quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_double_quote = False
            continue
        if in_backtick:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "`":
                in_backtick = False
            continue
        if ch == "'":
            in_single_quote = True
            continue
        if ch == '"':
            in_double_quote = True
            continue
        if ch == "`":
            in_backtick = True
            continue

        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return args_str[:i].strip()

    return args_str.strip()


def _is_dynamic_js_cmd(first_arg: str) -> bool:
    """Determines whether a JS command argument is dynamic or variable-driven."""
    first_arg = first_arg.strip()
    if not first_arg:
        return False
    if first_arg.startswith("`") and "${" in first_arg:
        return True
    if (first_arg.startswith('"') and first_arg.endswith('"')) or (first_arg.startswith("'") and first_arg.endswith("'")):
        if "+" in first_arg:
            return True
        return False
    if first_arg.startswith("`") and first_arg.endswith("`") and "${" not in first_arg:
        return False
    if re.match(r"^[a-zA-Z_$][a-zA-Z0-9_$.]*", first_arg):
        return True
    if "+" in first_arg:
        return True
    return True


def _references_environ(node: ast.AST, env_aliases: Optional[Set[str]] = None) -> bool:
    """Returns True if the AST node directly or indirectly references os.environ."""
    aliases = env_aliases or set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr == "environ":
            return True
        if isinstance(sub, ast.Name) and (sub.id == "environ" or sub.id in aliases):
            return True
    return False


def _is_constant_string_cmd(cmd_node: Optional[ast.AST]) -> bool:
    """Returns True if the command AST node is a string constant or list/tuple of string constants."""
    if cmd_node is None:
        return False
    if isinstance(cmd_node, ast.Constant) and isinstance(cmd_node.value, str):
        return True
    if isinstance(cmd_node, (ast.List, ast.Tuple)):
        return all(isinstance(elt, ast.Constant) and isinstance(elt.value, str) for elt in cmd_node.elts)
    return False


class EnvEgressGuard(BaseScannerPlugin):
    """
    Detects ambient LLM/API secret leakage into agent subprocesses and unrestricted
    network egress in agent containers.
    """

    supports_binary: bool = False

    def __init__(self, config=None):
        self.config = config or {}

    @property
    def name(self) -> str:
        return "env_egress_guard"

    @property
    def description(self) -> str:
        return "Detects ambient LLM/API secret leakage into agent subprocesses and unrestricted network egress in agent containers."

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for file_path in files:
            try:
                if not os.path.isfile(file_path):
                    continue

                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > 2 * 1024 * 1024:
                        logger.debug(f"Skipping {file_path}: size {file_size} exceeds 2 MB limit")
                        continue
                except OSError as e:
                    logger.debug(f"Failed to check size for {file_path}: {e}")
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    logger.debug(f"Failed to read file {file_path}: {e}")
                    continue

                filename_lower = os.path.basename(file_path).lower()

                if filename_lower.endswith(".py"):
                    findings.extend(self._scan_python(file_path, content))
                elif any(filename_lower.endswith(ext) for ext in (".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx")):
                    findings.extend(self._scan_javascript(file_path, content))
                elif (
                    filename_lower in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
                    or (filename_lower.startswith(("docker-compose.", "compose.")) and (filename_lower.endswith(".yml") or filename_lower.endswith(".yaml")))
                    or filename_lower == "devcontainer.json"
                ):
                    findings.extend(self._scan_container(file_path, content))

            except Exception as e:
                logger.debug(f"Error during env_egress_guard scan for {file_path}: {e}")

        return findings

    def _scan_python(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Zero-FP context gate: File MUST contain at least one AI indicator
        if not any(indicator in content for indicator in PYTHON_AI_INDICATORS):
            return findings

        lines = content.splitlines()

        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            logger.debug(f"Syntax error parsing Python AST for {file_path}: {e}")
            return findings
        except Exception as e:
            logger.debug(f"Unexpected AST parse error for {file_path}: {e}")
            return findings

        imports: Dict[str, str] = {}
        from_imports: Dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    alias_name = alias.asname or alias.name
                    imports[alias_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    alias_name = alias.asname or alias.name
                    if alias.name == "*":
                        if mod == "subprocess":
                            for fn in ["run", "Popen", "call", "check_output", "check_call"]:
                                from_imports[fn] = f"subprocess.{fn}"
                        elif mod == "asyncio":
                            for fn in ["create_subprocess_exec", "create_subprocess_shell"]:
                                from_imports[fn] = f"asyncio.{fn}"
                        elif mod == "os":
                            for fn in ["system", "popen"]:
                                from_imports[fn] = f"os.{fn}"
                    else:
                        from_imports[alias_name] = f"{mod}.{alias.name}" if mod else alias.name

        # Track simple local variable assignments referencing os.environ
        env_aliases: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if _references_environ(node.value):
                            env_aliases.add(target.id)

        def resolve_func_name(func_node: ast.AST) -> str:
            if isinstance(func_node, ast.Name):
                return from_imports.get(func_node.id, func_node.id)
            elif isinstance(func_node, ast.Attribute):
                if isinstance(func_node.value, ast.Name):
                    base_mod = imports.get(func_node.value.id, func_node.value.id)
                    return f"{base_mod}.{func_node.attr}"
                elif isinstance(func_node.value, ast.Attribute):
                    parent = resolve_func_name(func_node.value)
                    if parent:
                        return f"{parent}.{func_node.attr}"
            return ""

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = resolve_func_name(node.func)
            lineno = getattr(node, "lineno", 1)

            if 1 <= lineno <= len(lines):
                line_content = lines[lineno - 1]
            else:
                line_content = ""

            # Check os.system / os.popen
            if func_name in OS_TARGETS:
                if _is_line_suppressed(line_content, "shadow_env_subprocess_leak"):
                    continue

                if node.args:
                    arg0 = node.args[0]
                    is_plain_str = isinstance(arg0, ast.Constant) and isinstance(arg0.value, str)
                    if not is_plain_str:
                        findings.append({
                            "file": file_path,
                            "line": lineno,
                            "name": "shadow_env_subprocess_leak",
                            "severity": "HIGH",
                            "message": f"Dynamic execution via {func_name} inherits ambient process environment containing LLM API credentials.",
                            "context": line_content.strip()[:120]
                        })
                else:
                    findings.append({
                        "file": file_path,
                        "line": lineno,
                        "name": "shadow_env_subprocess_leak",
                        "severity": "HIGH",
                        "message": f"Execution via {func_name} inherits ambient process environment containing LLM API credentials.",
                        "context": line_content.strip()[:120]
                    })
                continue

            # Check subprocess.* and asyncio.create_subprocess_*
            if func_name in SUBPROCESS_TARGETS:
                if _is_line_suppressed(line_content, "shadow_env_subprocess_leak"):
                    continue

                env_kw = next((kw for kw in node.keywords if kw.arg == "env"), None)
                shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)

                is_shell_true = False
                if func_name == "asyncio.create_subprocess_shell":
                    is_shell_true = True
                elif shell_kw:
                    if isinstance(shell_kw.value, ast.Constant):
                        is_shell_true = bool(shell_kw.value.value)
                    else:
                        is_shell_true = True

                if env_kw is not None:
                    env_val = env_kw.value
                    is_env_none = isinstance(env_val, ast.Constant) and env_val.value is None

                    if not is_env_none:
                        if _references_environ(env_val, env_aliases):
                            findings.append({
                                "file": file_path,
                                "line": lineno,
                                "name": "shadow_env_subprocess_leak",
                                "severity": "HIGH",
                                "message": f"{func_name} explicitly passes ambient os.environ containing LLM API credentials to child process.",
                                "context": line_content.strip()[:120]
                            })
                        # Case B: Safe explicit allowlist -> DO NOT flag!
                        continue

                # Case C: env is omitted or env=None
                cmd_node = None
                if node.args:
                    cmd_node = node.args[0]
                else:
                    args_kw = next((kw for kw in node.keywords if kw.arg == "args"), None)
                    if args_kw:
                        cmd_node = args_kw.value

                is_const_cmd = _is_constant_string_cmd(cmd_node)

                if is_shell_true or not is_const_cmd:
                    findings.append({
                        "file": file_path,
                        "line": lineno,
                        "name": "shadow_env_subprocess_leak",
                        "severity": "HIGH",
                        "message": f"{func_name} executes dynamic command or shell=True without an explicit env allowlist, inheriting ambient LLM credentials.",
                        "context": line_content.strip()[:120]
                    })

        return findings

    def _scan_javascript(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Zero-FP context gate: File MUST contain at least one JS AI indicator
        if not any(indicator in content for indicator in JS_AI_INDICATORS):
            return findings

        # High FP regression fix: child_process MUST be referenced/imported
        if "child_process" not in content:
            return findings

        # Extract allowed child_process module namespace prefixes
        allowed_prefixes: Set[str] = {"child_process"}
        for m in re.finditer(r"(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*[\'\"][^\'\"]*child_process[\'\"]\s*\)", content):
            allowed_prefixes.add(m.group(1))
        for m in re.finditer(r"import\s+(?:\*\s+as\s+|)([a-zA-Z_$][a-zA-Z0-9_$]*)\s+from\s*[\'\"][^\'\"]*child_process[\'\"]", content):
            name = m.group(1).strip()
            if name and not name.startswith("{"):
                allowed_prefixes.add(name)
        for m in re.finditer(r"import\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*[\'\"][^\'\"]*child_process[\'\"]\s*\)", content):
            allowed_prefixes.add(m.group(1))

        prefix_regex = "|".join(re.escape(p) for p in allowed_prefixes)
        call_pattern = re.compile(
            rf"(?:(?:\b(?:{prefix_regex})\s*\.\s*)|(?<![\.\w$]))(exec|execSync|spawn|spawnSync|execFile)\s*\("
        )

        lines = content.splitlines()

        for match in call_pattern.finditer(content):
            func_name = match.group(1)
            start_paren_idx = match.end() - 1
            call_line = content[:match.start()].count("\n") + 1

            if 1 <= call_line <= len(lines):
                line_content = lines[call_line - 1]
                if _is_line_suppressed(line_content, "shadow_env_subprocess_leak"):
                    continue
            else:
                line_content = ""

            args_str = _extract_paren_content(content, start_paren_idx)

            # Check for explicit ambient process.env leak
            if re.search(r"env\s*:\s*process\.env|\.\.\.process\.env", args_str):
                findings.append({
                    "file": file_path,
                    "line": call_line,
                    "name": "shadow_env_subprocess_leak",
                    "severity": "HIGH",
                    "message": f"Subprocess call {func_name} passes ambient process.env to child process, risking LLM credential leakage.",
                    "context": line_content.strip()[:120]
                })
                continue

            # Check dynamic execution without explicit allowlist for exec, execSync, spawn
            if func_name in ("exec", "execSync", "spawn"):
                first_arg = _get_first_js_argument(args_str)
                if _is_dynamic_js_cmd(first_arg):
                    has_allowlist = bool(re.search(r"env\s*:\s*\{", args_str))
                    if not has_allowlist:
                        findings.append({
                            "file": file_path,
                            "line": call_line,
                            "name": "shadow_env_subprocess_leak",
                            "severity": "HIGH",
                            "message": f"Subprocess call {func_name} executes dynamic command without an explicit env allowlist, inheriting process.env credentials.",
                            "context": line_content.strip()[:120]
                        })

        return findings

    def _scan_container(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Zero-FP context gate: Container manifest MUST reference an AI workload
        content_lower = content.lower()
        if not any(workload in content_lower for workload in AI_CONTAINER_WORKLOADS):
            return findings

        lines = content.splitlines()
        filename_lower = os.path.basename(file_path).lower()

        # DevContainer check
        if filename_lower == "devcontainer.json":
            try:
                stripped_json = _strip_json_comments(content)
                data = json.loads(stripped_json)
                run_args = data.get("runArgs", [])
                has_host_net = False

                if isinstance(run_args, list):
                    for idx, arg in enumerate(run_args):
                        if arg in ("--network=host", "--net=host"):
                            has_host_net = True
                            break
                        if arg in ("--network", "--net") and idx + 1 < len(run_args) and run_args[idx + 1] == "host":
                            has_host_net = True
                            break

                if has_host_net:
                    target_line = 1
                    for line_idx, line in enumerate(lines):
                        if any(pattern in line for pattern in ("network=host", "net=host", "runArgs")):
                            target_line = line_idx + 1
                            break

                    line_text = lines[target_line - 1] if target_line <= len(lines) else ""
                    if not _is_line_suppressed(line_text, "agent_egress_host_network"):
                        findings.append({
                            "file": file_path,
                            "line": target_line,
                            "name": "agent_egress_host_network",
                            "severity": "CRITICAL",
                            "message": "DevContainer configuration specifies host network mode (--network=host), granting agent unrestricted host network access.",
                            "context": line_text.strip()[:120]
                        })
            except Exception as e:
                logger.debug(f"Failed to parse DevContainer JSON {file_path}: {e}")

            return findings

        # Docker Compose check
        host_network_directive_present = False
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if re.search(r"network_mode:\s*[\"']?host[\"']?", stripped, re.IGNORECASE):
                host_network_directive_present = True
                if not _is_line_suppressed(line, "agent_egress_host_network"):
                    findings.append({
                        "file": file_path,
                        "line": idx + 1,
                        "name": "agent_egress_host_network",
                        "severity": "CRITICAL",
                        "message": "Docker Compose service specifies network_mode: host, granting autonomous agent full host network access.",
                        "context": stripped[:120]
                    })

        if not host_network_directive_present:
            has_volumes = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if re.search(r"^\s*volumes\s*:", line):
                    has_volumes = True
                    break

            if has_volumes:
                has_isolation = False
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if re.search(r"internal:\s*true", stripped, re.IGNORECASE):
                        has_isolation = True
                        break
                    if re.search(r"network_mode:\s*[\"']?none[\"']?", stripped, re.IGNORECASE):
                        has_isolation = True
                        break
                    if re.search(r"\b(?:egress_firewall|egress-network|squid|egress-proxy)\b", stripped, re.IGNORECASE):
                        has_isolation = True
                        break

                if not has_isolation:
                    target_line = None
                    target_line_text = ""

                    for idx, line in enumerate(lines):
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        m = re.match(r"^\s{2,4}([a-zA-Z0-9_-]+)\s*:", line)
                        if m:
                            svc_name = m.group(1).lower()
                            if any(workload in svc_name for workload in AI_CONTAINER_WORKLOADS):
                                target_line = idx + 1
                                target_line_text = stripped
                                break

                    if target_line is None:
                        for idx, line in enumerate(lines):
                            stripped = line.strip()
                            if stripped.startswith("#"):
                                continue
                            if re.search(r"image:\s*.*(?:" + "|".join(AI_CONTAINER_WORKLOADS) + ")", stripped, re.IGNORECASE):
                                target_line = idx + 1
                                target_line_text = stripped
                                break

                    if target_line is None:
                        for idx, line in enumerate(lines):
                            stripped = line.strip()
                            if stripped.startswith("#"):
                                continue
                            if re.match(r"^\s*services\s*:", line):
                                target_line = idx + 1
                                target_line_text = stripped
                                break

                    if target_line is None:
                        target_line = 1
                        target_line_text = lines[0].strip() if lines else ""

                    if target_line <= len(lines):
                        if not _is_line_suppressed(lines[target_line - 1], "agent_egress_unrestricted"):
                            findings.append({
                                "file": file_path,
                                "line": target_line,
                                "name": "agent_egress_unrestricted",
                                "severity": "MEDIUM",
                                "message": "AI agent container mounts host volumes without network egress isolation (lacks internal: true or network_mode: none).",
                                "context": target_line_text[:120]
                            })

        return findings
