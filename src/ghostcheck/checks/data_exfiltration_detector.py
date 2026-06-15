import ast
import os
import math
import re
import logging
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)


try:
    import esprima
except ImportError:
    esprima = None

# Match potential key/token candidates (base64, hex, or typical high-density strings)
TOKEN_CANDIDATE_PAT = re.compile(r'\b[a-zA-Z0-9+/=_-]{23,128}\b')

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for char in set(text):
        p_x = text.count(char) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def has_high_entropy_token(text: str) -> bool:
    candidates = TOKEN_CANDIDATE_PAT.findall(text)
    for cand in candidates:
        if calculate_entropy(cand) > 4.5:
            return True
    return False


class WrapperHarvester(ast.NodeVisitor):
    def __init__(self, aliases):
        self.aliases = aliases
        self.custom_wrappers = set()
        self.current_function = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_name(node.func)
        if self._is_llm_api(func_name):
            if self.current_function:
                self.custom_wrappers.add(self.current_function)
        self.generic_visit(node)

    def _resolve_name(self, node) -> str:
        if isinstance(node, ast.Call):
            return self._resolve_name(node.func)
        elif isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            val_name = self._resolve_name(node.value)
            if val_name:
                return f"{val_name}.{node.attr}"
        return ""

    def _is_llm_api(self, name: str) -> bool:
        parts = name.split('.')
        return any(x in parts for x in ['completions', 'messages', 'invoke', 'generateContent'])


class PythonDataExfiltrationVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, custom_wrappers: set, aliases: dict):
        self.file_path = file_path
        self.custom_wrappers = custom_wrappers
        self.aliases = aliases.copy()
        self.findings = []
        self.scopes = [{}]  # global scope mapping var_name -> {"value": val, "taint": taint}
        self.in_mcp_tool = False

    def _resolve_name(self, node) -> str:
        if isinstance(node, ast.Call):
            return self._resolve_name(node.func)
        elif isinstance(node, ast.Name):
            for scope in reversed(self.scopes):
                if node.id in scope:
                    t = scope[node.id].get("taint")
                    if t:
                        return t
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            val_name = self._resolve_name(node.value)
            if val_name:
                return f"{val_name}.{node.attr}"
        return ""

    def _resolve_expression(self, node) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            for scope in reversed(self.scopes):
                if node.id in scope:
                    val = scope[node.id].get("value")
                    if val is not None:
                        return val
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            val = self._resolve_expression(node.value)
            if isinstance(val, str):
                return f"{val}.{node.attr}"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_expression(node.left)
            right = self._resolve_expression(node.right)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        elif isinstance(node, ast.Call):
            func_name = self._resolve_name(node.func)
            if func_name in ['Path', 'pathlib.Path'] and node.args:
                return self._resolve_expression(node.args[0])
        return None

    def _is_sensitive_name(self, name: str) -> bool:
        name_lower = name.lower()
        return any(k in name_lower for k in ['api_key', 'secret', 'password', 'token', 'private_key', 'passphrase', 'credentials'])

    def _is_sensitive_path(self, path: str) -> bool:
        normalized = path.replace('\\', '/')
        parts = normalized.split('/')
        sensitive_parts = ['.env', '.ssh', '.aws', 'id_rsa', 'credentials']
        for p in parts:
            if any(s in p for s in sensitive_parts):
                if any(x in p for x in ['.example', '.template', '.dist', '.pub']):
                    continue
                return True
        return False

    def _is_public_directory(self, path: str) -> bool:
        normalized = path.replace('\\', '/')
        public_dirs = ['public/', 'dist/', 'static/', 'assets/', 'web/']
        return any(pub in normalized for pub in public_dirs) or normalized.startswith('public/') or normalized.startswith('dist/') or normalized.startswith('static/') or normalized.startswith('assets/') or normalized.startswith('web/')

    def _check_expression_for_taint(self, node) -> str:
        class TaintChecker(ast.NodeVisitor):
            def __init__(self, visitor_parent):
                self.parent = visitor_parent
                self.taint_found = None
                
            def visit_Name(self, name_node: ast.Name):
                for scope in reversed(self.parent.scopes):
                    if name_node.id in scope:
                        t = scope[name_node.id].get("taint")
                        if t and t not in ['mcp_sensitive_leak', 'public_write_handle']:
                            self.taint_found = t
                            return
                if name_node.id in self.parent.aliases:
                    resolved = self.parent.aliases[name_node.id]
                    if resolved in ['os.environ', 'environ']:
                        self.taint_found = 'env'
                        return
                if self.parent._is_sensitive_name(name_node.id):
                    self.taint_found = 'sensitive'
                    return

            def visit_Attribute(self, attr_node: ast.Attribute):
                resolved = self.parent._resolve_name(attr_node)
                if resolved in ['os.environ', 'os.getenv', 'environ']:
                    self.taint_found = 'env'
                    return
                self.generic_visit(attr_node)
                
            def visit_Call(self, call_node: ast.Call):
                func_resolved = self.parent._resolve_name(call_node.func)
                if func_resolved in ['os.getenv', 'os.environ.get', 'environ.get']:
                    self.taint_found = 'env'
                    return
                self.generic_visit(call_node)

            def visit_Constant(self, const_node: ast.Constant):
                if isinstance(const_node.value, str):
                    if has_high_entropy_token(const_node.value):
                        self.taint_found = 'high_entropy'
                        return
                    if self.parent._is_sensitive_name(const_node.value):
                        self.taint_found = 'sensitive'
                        return

        checker = TaintChecker(self)
        checker.visit(node)
        return checker.taint_found

    def _check_mcp_sensitive_read(self, node) -> bool:
        if not isinstance(node, ast.Call):
            return False
        func_name = self._resolve_name(node.func)
        if func_name == 'open' and node.args:
            path_val = self._resolve_expression(node.args[0])
            if isinstance(path_val, str) and self._is_sensitive_path(path_val):
                return True
        elif func_name.endswith('.read') or func_name.endswith('.read_text') or func_name.endswith('.read_bytes'):
            if isinstance(node.func, ast.Attribute):
                caller_val = self._resolve_expression(node.func.value)
                if isinstance(caller_val, str) and self._is_sensitive_path(caller_val):
                    return True
                elif isinstance(node.func.value, ast.Call):
                    sub_func = self._resolve_name(node.func.value.func)
                    if sub_func in ['open', 'Path', 'pathlib.Path'] and node.func.value.args:
                        sub_path = self._resolve_expression(node.func.value.args[0])
                        if isinstance(sub_path, str) and self._is_sensitive_path(sub_path):
                            return True
        return False

    def _check_public_write_handle(self, node) -> bool:
        if not isinstance(node, ast.Call):
            return False
        func_name = self._resolve_name(node.func)
        if func_name == 'open' and node.args:
            path_val = self._resolve_expression(node.args[0])
            if isinstance(path_val, str) and self._is_public_directory(path_val):
                mode = 'r'
                if len(node.args) > 1:
                    mode_val = self._resolve_expression(node.args[1])
                    if isinstance(mode_val, str):
                        mode = mode_val
                for kw in node.keywords:
                    if kw.arg == 'mode':
                        kw_val = self._resolve_expression(kw.value)
                        if isinstance(kw_val, str):
                            mode = kw_val
                if any(x in mode for x in ['w', 'a', 'x']):
                    return True
        return False

    def _is_mcp_sensitive_expression(self, node) -> bool:
        if self._check_mcp_sensitive_read(node):
            return True
            
        class MCPTaintChecker(ast.NodeVisitor):
            def __init__(self, visitor_parent):
                self.parent = visitor_parent
                self.leak_found = False
                
            def visit_Name(self, name_node: ast.Name):
                for scope in reversed(self.parent.scopes):
                    if name_node.id in scope:
                        t = scope[name_node.id].get("taint")
                        if t == 'mcp_sensitive_leak':
                            self.leak_found = True
                            return
                        
            def visit_Call(self, call_node: ast.Call):
                if self.parent._check_mcp_sensitive_read(call_node):
                    self.leak_found = True
                    return
                self.generic_visit(call_node)

        checker = MCPTaintChecker(self)
        checker.visit(node)
        return checker.leak_found

    def _is_public_write_handle_var(self, node) -> bool:
        if isinstance(node, ast.Name):
            for scope in reversed(self.scopes):
                if node.id in scope:
                    t = scope[node.id].get("taint")
                    if t == 'public_write_handle':
                        return True
        return False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.aliases[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.aliases[asname] = f"{module}.{name}"
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        is_mcp = False
        if node.decorator_list:
            for dec in node.decorator_list:
                dec_name = self._resolve_name(dec)
                if any(x in dec_name for x in ['mcp.tool', 'mcp.image', 'mcp.resource', 'fastmcp.tool', 'tool']):
                    is_mcp = True
                    break

        old_mcp = self.in_mcp_tool
        if not is_mcp:
            if any('mcp' in v or 'fastmcp' in v for v in self.aliases.values()):
                is_mcp = True

        self.in_mcp_tool = is_mcp
        self.scopes.append({})
        self.generic_visit(node)
        self.scopes.pop()
        self.in_mcp_tool = old_mcp

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_With(self, node: ast.With):
        for item in node.items:
            if self._check_mcp_sensitive_read(item.context_expr):
                if isinstance(item.optional_vars, ast.Name):
                    self.scopes[-1][item.optional_vars.id] = {"value": None, "taint": 'mcp_sensitive_leak'}
            elif self._check_public_write_handle(item.context_expr):
                if isinstance(item.optional_vars, ast.Name):
                    self.scopes[-1][item.optional_vars.id] = {"value": None, "taint": 'public_write_handle'}
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        taint = None
        val = self._resolve_expression(node.value)
        
        if self._check_mcp_sensitive_read(node.value):
            taint = 'mcp_sensitive_leak'
        elif self._check_public_write_handle(node.value):
            taint = 'public_write_handle'
        elif self._is_mcp_sensitive_expression(node.value):
            taint = 'mcp_sensitive_leak'
        else:
            if isinstance(val, str):
                if val in ['os.environ', 'os.getenv', 'environ']:
                    taint = 'env'
                elif self._is_sensitive_name(val):
                    taint = 'sensitive'
                elif has_high_entropy_token(val):
                    taint = 'high_entropy'

            if not taint:
                taint = self._check_expression_for_taint(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                self.scopes[-1][target.id] = {"value": val, "taint": taint}
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self.scopes[-1][elt.id] = {"value": val, "taint": taint}
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if self.in_mcp_tool and node.value:
            if self._is_mcp_sensitive_expression(node.value):
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "AI Data Exfiltration: MCP Tool File Leakage",
                    "severity": "CRITICAL",
                    "message": "MCP tool returns sensitive file content directly to LLM context.",
                    "suggestion": "Do not return raw sensitive file content in MCP tools. Parse, filter, or restrict tool access."
                })
        self.generic_visit(node)

    def _is_llm_api(self, name: str) -> bool:
        parts = name.split('.')
        return any(x in parts for x in ['completions', 'messages', 'invoke', 'generateContent'])

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_name(node.func)
        line = node.lineno

        # 1. AC1: LLM API Prompt Leakage
        if self._is_llm_api(func_name) or func_name in self.custom_wrappers:
            for arg in node.args:
                taint = self._check_expression_for_taint(arg)
                if taint:
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "AI Data Exfiltration: LLM Prompt Leakage",
                        "severity": "HIGH",
                        "message": f"Potential sensitive data exfiltration to LLM API call '{func_name}' via tainted prompt argument.",
                        "suggestion": "Sanitize prompts and remove sensitive environment variables, high-entropy keys, or credentials before invoking LLM APIs."
                    })
            for kw in node.keywords:
                if kw.arg in ['messages', 'prompt', 'input', 'content', 'text']:
                    taint = self._check_expression_for_taint(kw.value)
                    if taint:
                        self.findings.append({
                            "file": self.file_path,
                            "line": line,
                            "name": "AI Data Exfiltration: LLM Prompt Leakage",
                            "severity": "HIGH",
                            "message": f"Potential sensitive data exfiltration to LLM API call '{func_name}' via keyword argument '{kw.arg}'.",
                            "suggestion": "Sanitize prompts and remove sensitive environment variables, high-entropy keys, or credentials before invoking LLM APIs."
                        })

        # 2. AC3: Public Directory Sensitive Write (chain open(...).write(...))
        elif func_name.endswith('.write'):
            if isinstance(node.func, ast.Attribute):
                caller_val = self._resolve_expression(node.func.value)
                if caller_val == 'public_write_handle' or self._is_public_write_handle_var(node.func.value) or self._check_public_write_handle(node.func.value):
                    if node.args:
                        taint = self._check_expression_for_taint(node.args[0])
                        if taint:
                            self.findings.append({
                                "file": self.file_path,
                                "line": line,
                                "name": "AI Data Exfiltration: Public Output Leakage",
                                "severity": "MEDIUM",
                                "message": "Potential sensitive data written to a public web directory.",
                                "suggestion": "Avoid writing sensitive user data, API keys, or environment variables to public web directories like static/ or public/."
                            })

        # Pathlib write_text / write_bytes
        elif func_name.endswith('.write_text') or func_name.endswith('.write_bytes'):
            if isinstance(node.func, ast.Attribute):
                caller_val = self._resolve_expression(node.func.value)
                is_public_write = False
                if isinstance(caller_val, str) and self._is_public_directory(caller_val):
                    is_public_write = True

                if is_public_write and node.args:
                    taint = self._check_expression_for_taint(node.args[0])
                    if taint:
                        self.findings.append({
                            "file": self.file_path,
                            "line": line,
                            "name": "AI Data Exfiltration: Public Output Leakage",
                            "severity": "MEDIUM",
                            "message": "Potential sensitive data written to a public web directory.",
                            "suggestion": "Avoid writing sensitive user data, API keys, or environment variables to public web directories like static/ or public/."
                        })

        # Shutil copyfile / copy
        elif func_name in ['shutil.copy', 'shutil.copyfile', 'copy', 'copyfile'] and len(node.args) >= 2:
            src_val = self._resolve_expression(node.args[0])
            dst_val = self._resolve_expression(node.args[1])
            if isinstance(src_val, str) and self._is_sensitive_path(src_val):
                if isinstance(dst_val, str) and self._is_public_directory(dst_val):
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "AI Data Exfiltration: Public Output Leakage",
                        "severity": "MEDIUM",
                        "message": "Potential sensitive file copied to a public web directory.",
                        "suggestion": "Avoid copying sensitive files like .env or id_rsa to public web directories."
                    })

        # Symlink Creation
        elif func_name in ['os.symlink', 'symlink'] and len(node.args) >= 2:
            src_val = self._resolve_expression(node.args[0])
            dst_val = self._resolve_expression(node.args[1])
            is_bad = False
            if isinstance(src_val, str) and self._is_sensitive_path(src_val):
                is_bad = True
            if isinstance(dst_val, str) and self._is_public_directory(dst_val):
                is_bad = True
            if is_bad:
                self.findings.append({
                    "file": self.file_path,
                    "line": line,
                    "name": "AI Data Exfiltration: Symlink Creation Guard",
                    "severity": "CRITICAL",
                    "message": "Dangerous symlink creation involving a sensitive path or a public web directory.",
                    "suggestion": "Avoid creating symlinks to sensitive files or inside public directories."
                })

        self.generic_visit(node)


class JsDataExfiltrationVisitor:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.scopes = [{}]
        self.in_mcp_tool = False
        self.has_mcp = False

    def push_scope(self):
        self.scopes.append({})

    def pop_scope(self):
        if self.scopes:
            self.scopes.pop()

    def _get_line(self, node) -> int:
        loc = getattr(node, 'loc', None)
        if loc:
            start = getattr(loc, 'start', None)
            if start:
                line_val = getattr(start, 'line', None)
                if line_val is not None:
                    return line_val
        return 1

    def _resolve_expression(self, node) -> str:
        if not node:
            return ""
        n_type = getattr(node, 'type', '')
        if n_type == 'Identifier':
            var_name = getattr(node, 'name', '')
            for scope in reversed(self.scopes):
                if var_name in scope:
                    val = scope[var_name].get("value")
                    if val is not None:
                        return val
            return var_name
        elif n_type == 'Literal':
            val = getattr(node, 'value', None)
            return str(val) if val is not None else ""
        elif n_type == 'MemberExpression':
            obj_str = self._resolve_expression(node.object)
            prop_str = self._resolve_expression(node.property)
            if obj_str and prop_str:
                return f"{obj_str}.{prop_str}"
            return prop_str or obj_str
        elif n_type == 'BinaryExpression' and getattr(node, 'operator', '') == '+':
            left = self._resolve_expression(node.left)
            right = self._resolve_expression(node.right)
            return left + right
        return ""

    def _is_sensitive_path(self, path: str) -> bool:
        normalized = path.replace('\\', '/')
        parts = normalized.split('/')
        sensitive_parts = ['.env', '.ssh', '.aws', 'id_rsa', 'credentials']
        for p in parts:
            if any(s in p for s in sensitive_parts):
                if any(x in p for x in ['.example', '.template', '.dist', '.pub']):
                    continue
                return True
        return False

    def _is_public_directory(self, path: str) -> bool:
        normalized = path.replace('\\', '/')
        public_dirs = ['public/', 'dist/', 'static/', 'assets/', 'web/']
        return any(pub in normalized for pub in public_dirs) or normalized.startswith('public/') or normalized.startswith('dist/') or normalized.startswith('static/') or normalized.startswith('assets/') or normalized.startswith('web/')

    def _check_expression_for_taint(self, node) -> str:
        found_taint = [None]
        
        def walk_node(n):
            if not n:
                return
            n_type = getattr(n, 'type', '')
            if n_type == 'Identifier':
                name = getattr(n, 'name', '')
                for scope in reversed(self.scopes):
                    if name in scope:
                        t = scope[name].get("taint")
                        if t:
                            found_taint[0] = t
                            return
            elif n_type == 'MemberExpression':
                expr_str = self._resolve_expression(n)
                if expr_str.startswith('process.env'):
                    found_taint[0] = 'env'
                    return
            elif n_type == 'Literal':
                val = getattr(n, 'value', None)
                if isinstance(val, str):
                    if has_high_entropy_token(val):
                        found_taint[0] = 'high_entropy'
                        return
                    if any(k in val.lower() for k in ['api_key', 'secret', 'password', 'token', 'private_key']):
                        found_taint[0] = 'sensitive'
                        return

            for key, value in n.__dict__.items():
                if found_taint[0]:
                    return
                if isinstance(value, list):
                    for item in value:
                        if hasattr(item, 'type'):
                            walk_node(item)
                elif hasattr(value, 'type'):
                    walk_node(value)

        walk_node(node)
        return found_taint[0]

    def walk(self, node):
        if not node:
            return
        
        node_type = getattr(node, 'type', '')
        line = self._get_line(node)
        
        is_function = node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'MethodDefinition']
        is_class = node_type in ['ClassDeclaration', 'ClassExpression']

        if is_function:
            old_mcp = self.in_mcp_tool
            if self.has_mcp:
                self.in_mcp_tool = True
            self.push_scope()
        elif is_class:
            self.push_scope()

        if node_type == 'VariableDeclarator':
            init_val = getattr(node, 'init', None)
            id_name = getattr(getattr(node, 'id', None), 'name', '')
            if id_name and init_val:
                val = self._resolve_expression(init_val)
                taint = None
                init_str = self._resolve_expression(init_val)
                if init_str.startswith('process.env'):
                    taint = 'env'
                elif self._is_sensitive_path(init_str):
                    taint = 'mcp_sensitive_leak'
                else:
                    taint = self._check_expression_for_taint(init_val)
                self.scopes[-1][id_name] = {"value": val, "taint": taint}

        elif node_type == 'AssignmentExpression':
            left_str = self._resolve_expression(node.left)
            if left_str:
                val = self._resolve_expression(node.right)
                taint = None
                right_str = self._resolve_expression(node.right)
                if right_str.startswith('process.env'):
                    taint = 'env'
                elif self._is_sensitive_path(right_str):
                    taint = 'mcp_sensitive_leak'
                else:
                    taint = self._check_expression_for_taint(node.right)
                self.scopes[-1][left_str] = {"value": val, "taint": taint}

        elif node_type == 'ImportDeclaration':
            source = getattr(getattr(node, 'source', None), 'value', '')
            if 'mcp' in source or 'fastmcp' in source:
                self.has_mcp = True

        elif node_type == 'CallExpression':
            callee_str = self._resolve_expression(node.callee)
            if callee_str == 'require' and node.arguments:
                arg_val = self._resolve_expression(node.arguments[0])
                if 'mcp' in arg_val or 'fastmcp' in arg_val:
                    self.has_mcp = True
            
            is_llm = False
            if any(x in callee_str for x in ['completions', 'messages', 'invoke', 'generateContent']):
                is_llm = True
            
            if is_llm:
                for arg in getattr(node, 'arguments', []):
                    taint = self._check_expression_for_taint(arg)
                    if taint:
                        self.findings.append({
                            "file": self.file_path,
                            "line": line,
                            "name": "AI Data Exfiltration: LLM Prompt Leakage",
                            "severity": "HIGH",
                            "message": f"Potential sensitive data exfiltration to LLM API call '{callee_str}' via tainted prompt argument.",
                            "suggestion": "Sanitize prompts and remove sensitive environment variables, high-entropy keys, or credentials before invoking LLM APIs."
                        })

            is_sensitive_read = False
            if callee_str in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile'] and node.arguments:
                path_val = self._resolve_expression(node.arguments[0])
                if isinstance(path_val, str) and self._is_sensitive_path(path_val):
                    is_sensitive_read = True

            if callee_str in ['fs.writeFileSync', 'fs.writeFile', 'fs.createWriteStream'] and node.arguments:
                path_val = self._resolve_expression(node.arguments[0])
                if isinstance(path_val, str) and self._is_public_directory(path_val):
                    if len(node.arguments) > 1:
                        taint = self._check_expression_for_taint(node.arguments[1])
                        if taint:
                            self.findings.append({
                                "file": self.file_path,
                                "line": line,
                                "name": "AI Data Exfiltration: Public Output Leakage",
                                "severity": "MEDIUM",
                                "message": "Potential sensitive data written to a public web directory.",
                                "suggestion": "Avoid writing sensitive user data, API keys, or environment variables to public web directories like static/ or public/."
                            })

        elif node_type == 'ReturnStatement' and node.argument:
            if self.in_mcp_tool:
                taint = self._check_expression_for_taint(node.argument)
                is_leak = False
                if taint == 'mcp_sensitive_leak':
                    is_leak = True
                else:
                    arg_type = getattr(node.argument, 'type', '')
                    if arg_type == 'CallExpression':
                        callee_str = self._resolve_expression(node.argument.callee)
                        if callee_str in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile'] and getattr(node.argument, 'arguments', None):
                            path_val = self._resolve_expression(node.argument.arguments[0])
                            if isinstance(path_val, str) and self._is_sensitive_path(path_val):
                                is_leak = True
                
                if is_leak:
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "AI Data Exfiltration: MCP Tool File Leakage",
                        "severity": "CRITICAL",
                        "message": "MCP tool returns sensitive file content directly to LLM context.",
                        "suggestion": "Do not return raw sensitive file content in MCP tools. Parse, filter, or restrict tool access."
                    })

        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.walk(item)
            elif hasattr(value, 'type'):
                self.walk(value)

        if is_function or is_class:
            self.pop_scope()
            if is_function:
                self.in_mcp_tool = old_mcp


class DataExfiltrationDetector(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "data_exfiltration_detector"

    @property
    def description(self) -> str:
        return "Detects data exfiltration risks in AI prompts, MCP tools, and web public directory outputs"

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        for file_path in files:
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in ['.py', '.js', '.ts', '.jsx', '.tsx']:
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                logger.debug(f"Failed to read file {file_path}: {e}", exc_info=True)
                continue

            reported = set()

            # 1. AST Scanning
            if ext == '.py':
                try:
                    tree = ast.parse(content, filename=file_path)
                    # Pass 1: Harvester to find custom wrappers
                    harvester = WrapperHarvester({})
                    harvester.visit(tree)
                    # Pass 2: Data Exfiltration Scan
                    visitor = PythonDataExfiltrationVisitor(file_path, harvester.custom_wrappers, harvester.aliases)
                    visitor.visit(tree)
                    for fnd in visitor.findings:
                        key = (fnd["line"], fnd["name"])
                        reported.add(key)
                        findings.append(fnd)
                except Exception as e:
                    # AST parsing fails (e.g. syntax error), fallback to text scan
                    logger.debug(f"Python AST parse failed for {file_path}, falling back to text scan: {e}", exc_info=True)

            elif ext in ['.js', '.ts', '.jsx', '.tsx'] and esprima is not None:
                try:
                    try:
                        tree = esprima.parseModule(content, loc=True)
                    except Exception:
                        tree = esprima.parseScript(content, loc=True)

                    visitor = JsDataExfiltrationVisitor(file_path)
                    visitor.walk(tree)
                    for fnd in visitor.findings:
                        key = (fnd["line"], fnd["name"])
                        reported.add(key)
                        findings.append(fnd)
                except Exception as e:
                    # Fallback to text scan on esprima exceptions
                    logger.debug(f"JS/TS AST parse failed for {file_path}, falling back to text scan: {e}", exc_info=True)

            # 2. Text-Based Regex Scanning (always run as defense-in-depth)
            text_findings = self.scan_text(file_path, content)
            for fnd in text_findings:
                key = (fnd["line"], fnd["name"])
                if key not in reported:
                    reported.add(key)
                    findings.append(fnd)

        return findings

    def _is_sensitive_name(self, name: str) -> bool:
        name_lower = name.lower()
        return any(k in name_lower for k in ['api_key', 'secret', 'password', 'token', 'private_key'])

    def _is_sensitive_path(self, path: str) -> bool:
        normalized = path.replace('\\', '/')
        parts = normalized.split('/')
        sensitive_parts = ['.env', '.ssh', '.aws', 'id_rsa', 'credentials']
        for p in parts:
            if any(s in p for s in sensitive_parts):
                if any(x in p for x in ['.example', '.template', '.dist', '.pub']):
                    continue
                return True
        return False

    def _is_public_directory(self, path: str) -> bool:
        normalized = path.replace('\\', '/')
        public_dirs = ['public/', 'dist/', 'static/', 'assets/', 'web/']
        return any(pub in normalized for pub in public_dirs) or normalized.startswith('public/') or normalized.startswith('dist/') or normalized.startswith('static/') or normalized.startswith('assets/') or normalized.startswith('web/')

    def scan_text(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        has_mcp_import = any(x in content for x in ['import mcp', 'require("mcp")', "require('mcp')", 'fastmcp'])
        tainted_vars = set()

        # Pass 1: Identify tainted variables (assignments from env or high-entropy or sensitive names)
        # Regex updated to support TypeScript type annotations optional syntax (e.g. const conf: Config = ...)
        assign_pat = re.compile(r'\b(?:const|let|var)?\s*([a-zA-Z0-9_]+)(?:\s*:\s*[a-zA-Z0-9_|<>\[\]\s]+)?\s*=\s*(.*)')
        for line in lines:
            trimmed = line.strip()
            if trimmed.startswith('#') or trimmed.startswith('//') or trimmed.startswith('*'):
                continue
            m = assign_pat.search(line)
            if m:
                var_name = m.group(1)
                right_side = m.group(2)
                is_tainted = False
                if any(x in right_side for x in ['os.environ', 'process.env', 'os.getenv', 'environ.get']):
                    is_tainted = True
                elif has_high_entropy_token(right_side):
                    is_tainted = True
                elif self._is_sensitive_name(var_name):
                    is_tainted = True
                
                if is_tainted:
                    tainted_vars.add(var_name)

        # Pass 2: Multi-line match LLM calls
        llm_call_pat = re.compile(r'\b(completions\.create|messages\.create|invoke|generateContent)\s*\(([\s\S]*?)\)', re.MULTILINE)
        for m in llm_call_pat.finditer(content):
            api_name = m.group(1)
            args_content = m.group(2)
            start_idx = m.start()
            line_num = content[:start_idx].count('\n') + 1

            has_leak = False
            if any(x in args_content for x in ['os.environ', 'process.env', 'os.getenv', 'environ.get']):
                has_leak = True
            elif any(v in args_content for v in tainted_vars):
                has_leak = True
            elif any(self._is_sensitive_name(token) for token in re.split(r'\W+', args_content)):
                has_leak = True
            elif has_high_entropy_token(args_content):
                has_leak = True

            if has_leak:
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "AI Data Exfiltration: LLM Prompt Leakage",
                    "severity": "HIGH",
                    "message": f"Potential sensitive data exfiltration to LLM API call '{api_name}' detected via text scan.",
                    "suggestion": "Sanitize prompts and remove sensitive environment variables, high-entropy keys, or credentials before invoking LLM APIs."
                })

        # Pass 3: Simple line-level fallback for reading sensitive files in files that use MCP
        for i, line in enumerate(lines):
            line_num = i + 1
            line_lower = line.lower()
            trimmed = line.strip()
            if trimmed.startswith('#') or trimmed.startswith('//') or trimmed.startswith('*'):
                continue

            if has_mcp_import:
                if any(x in line_lower for x in ['open(', 'readfilesync', 'readfile', 'read_text', 'read_bytes']) and self._is_sensitive_path(line_lower):
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": "AI Data Exfiltration: MCP Tool File Leakage",
                        "severity": "CRITICAL",
                        "message": "Potential MCP tool sensitive file read detected via text scan.",
                        "suggestion": "Do not return raw sensitive file content in MCP tools. Parse, filter, or restrict tool access."
                    })

            # AC3: Public Directory writes
            is_write = any(x in line for x in ['open(', 'writefilesync', 'writefile', 'write_text', 'write_bytes', 'createwritestream', 'copyfile'])
            if is_write and self._is_public_directory(line):
                has_sensitive = False
                if any(x in line for x in ['os.environ', 'process.env', 'os.getenv', 'environ.get']):
                    has_sensitive = True
                elif any(self._is_sensitive_name(token) for token in re.split(r'\W+', line)):
                    has_sensitive = True
                if not has_sensitive:
                    has_sensitive = has_high_entropy_token(line)
                    
                if has_sensitive:
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": "AI Data Exfiltration: Public Output Leakage",
                        "severity": "MEDIUM",
                        "message": "Potential sensitive data write to a public web directory detected via text scan.",
                        "suggestion": "Avoid writing sensitive user data, API keys, or environment variables to public web directories like static/ or public/."
                    })

        return findings
