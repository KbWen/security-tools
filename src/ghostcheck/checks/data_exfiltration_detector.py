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
TOKEN_CANDIDATE_PAT = re.compile(r'\b[a-zA-Z0-9+/=_-]{20,512}\b')

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

from typing import Optional

def strip_port_and_brackets(host: str) -> str:
    host = host.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    if "/" in host:
        host = host.split("/", 1)[0]
    
    if "]" in host:
        parts = host.split("]")
        ipv6_part = parts[0].strip("[]")
        return ipv6_part
    else:
        if host.count(":") == 1:
            return host.split(":")[0]
    return host.strip("[]")

def parse_ipv4_to_int(host: str) -> Optional[int]:
    host = host.strip("[]").lower()
    if not host:
        return None
    if "::ffff:" in host:
        suffix = host.split("::ffff:")[-1]
        if "." in suffix:
            val = parse_ipv4_to_int(suffix)
            if val is not None:
                return val
        else:
            parts = suffix.split(":")
            if len(parts) == 2:
                try:
                    val1 = int(parts[0], 16)
                    val2 = int(parts[1], 16)
                    return (val1 << 16) + val2
                except ValueError:
                    pass
        return None

    parts = host.split('.')
    if len(parts) > 4:
        return None
    try:
        values = []
        for p in parts:
            p = p.strip()
            if not p:
                return None
            if p.startswith('0x'):
                values.append(int(p, 16))
            elif p.startswith('0') and len(p) > 1 and all(c in '01234567' for c in p):
                values.append(int(p, 8))
            else:
                values.append(int(p, 10))
    except ValueError:
        return None

    num_parts = len(parts)
    if num_parts == 4:
        if all(0 <= v <= 255 for v in values):
            return (values[0] << 24) + (values[1] << 16) + (values[2] << 8) + values[3]
    elif num_parts == 3:
        if 0 <= values[0] <= 255 and 0 <= values[1] <= 255 and 0 <= values[2] <= 65535:
            return (values[0] << 24) + (values[1] << 16) + values[2]
    elif num_parts == 2:
        if 0 <= values[0] <= 255 and 0 <= values[1] <= 16777215:
            return (values[0] << 24) + values[1]
    elif num_parts == 1:
        # Convert to unsigned 32-bit integer (supports signed wrapping)
        try:
            val = values[0]
            val_u32 = val & 0xFFFFFFFF
            return val_u32
        except Exception:
            pass
    return None

def is_metadata_ip_or_host(text: str) -> bool:
    if not text:
        return False
    text = text.lower()
    if "metadata.google.internal" in text or "instance-data" in text:
        return True
    if "fd00:ec2::254" in text or "fd00:ec2:0:0:0:0:0:254" in text:
        return True
        
    url_hosts = re.findall(r'https?://([a-zA-Z0-9_\.\-\:\[\]]+)', text)
    dotted_patterns = re.findall(r'\b[a-zA-Z0-9_\.\-\:\[\]]+\b', text)
    candidates = list(set(url_hosts + dotted_patterns))
    target_uints = {2852039166, 2822734096, 1684301000, 3221225664}
    for cand in candidates:
        if not cand:
            continue
        cleaned = strip_port_and_brackets(cand)
        if not cleaned:
            continue
        if cleaned == "metadata" or cleaned.startswith("metadata:") or cleaned.endswith(".metadata"):
            return True
        if cleaned == "fd00:ec2::254" or cleaned == "fd00:ec2:0:0:0:0:0:254":
            return True
            
        ip_val = parse_ipv4_to_int(cleaned)
        if ip_val is not None and ip_val in target_uints:
            return True
    return False

class ValidationScanner(ast.NodeVisitor):
    def __init__(self):
        self.validated_names = set()
    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name in ['is_relative_to', 'realpath', 'abspath', 'is_safe', 'validate_path']:
            # Find any variable name passed as argument to validate
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self.validated_names.add(arg.id)
                elif isinstance(arg, ast.Call):
                    # path.resolve() etc
                    if isinstance(arg.func, ast.Attribute) and isinstance(arg.func.value, ast.Name):
                        self.validated_names.add(arg.func.value.id)
            # Find any variable name in the caller object (node.func.value)
            if isinstance(node.func, ast.Attribute):
                class NameVisitor(ast.NodeVisitor):
                    def __init__(self, names_set):
                        self.names_set = names_set
                    def visit_Name(self, n):
                        self.names_set.add(n.id)
                        self.generic_visit(n)
                NameVisitor(self.validated_names).visit(node.func.value)
        self.generic_visit(node)
    def visit_Compare(self, node: ast.Compare):
        # path == ".." or ".." in path
        var_name = None
        has_dots = False
        if isinstance(node.left, ast.Constant) and node.left.value == '..':
            has_dots = True
        elif isinstance(node.left, ast.Name):
            var_name = node.left.id
        for op in node.comparators:
            if isinstance(op, ast.Constant) and op.value == '..':
                has_dots = True
            elif isinstance(op, ast.Name):
                var_name = op.id
        if has_dots and var_name:
            self.validated_names.add(var_name)
        self.generic_visit(node)


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
            if isinstance(node.func, ast.Name) and node.func.id == 'getattr' and len(node.args) >= 2:
                obj = self._resolve_name(node.args[0])
                attr = self._resolve_expression(node.args[1])
                if obj and isinstance(attr, str):
                    return f"{obj}.{attr}"
            return self._resolve_name(node.func)
        elif isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            val_name = self._resolve_name(node.value)
            if val_name:
                return f"{val_name}.{node.attr}"
        return ""

    def _resolve_expression(self, node) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        return None

    def _is_llm_api(self, name: str) -> bool:
        parts = name.split('.')
        return any(x in parts for x in ['completions', 'messages', 'invoke', 'generateContent'])


class PythonDataExfiltrationVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, custom_wrappers: set, aliases: dict):
        self.file_path = file_path
        self.custom_wrappers = custom_wrappers
        self.aliases = aliases.copy()
        self.findings = []
        self.scopes = [{}]  # global scope mapping var_name -> {"value": val, "taint": taint, "sub_taints": {}}
        self.in_mcp_tool = False
        self.validated_vars = set()
        self.in_validation_context = False

    def _resolve_name(self, node) -> str:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'getattr' and len(node.args) >= 2:
                obj = self._resolve_name(node.args[0])
                attr = self._resolve_expression(node.args[1])
                if obj and isinstance(attr, str):
                    resolved = f"{obj}.{attr}"
                    return resolved
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
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for val in node.values:
                if isinstance(val, ast.Constant):
                    parts.append(str(val.value))
                else:
                    parts.append("{}")
            return "".join(parts)
        elif isinstance(node, ast.Call):
            func_name = self._resolve_name(node.func)
            if func_name in ['Path', 'pathlib.Path'] and node.args:
                return self._resolve_expression(node.args[0])
        return None

    def _is_sensitive_name(self, name: str) -> bool:
        name_lower = name.lower()
        return any(k in name_lower for k in ['api_key', 'secret', 'password', 'token', 'private_key', 'passphrase', 'credentials'])

    def _is_sensitive_path(self, path: str) -> bool:
        path = path.lower()
        normalized = path.replace('\\', '/')
        parts = normalized.split('/')
        sensitive_parts = ['.env', '.ssh', '.aws', 'id_rsa', 'credentials', 'passwd', 'shadow', 'sam']
        for p in parts:
            if any(s in p for s in sensitive_parts):
                if any(x in p for x in ['.example', '.template', '.dist', '.pub']):
                    continue
                return True
        return False

    def _is_public_directory(self, path: str) -> bool:
        path = path.lower()
        normalized = path.replace('\\', '/')
        public_dirs = ['public/', 'dist/', 'static/', 'assets/', 'web/']
        return any(pub in normalized for pub in public_dirs) or normalized.startswith('public/') or normalized.startswith('dist/') or normalized.startswith('static/') or normalized.startswith('assets/') or normalized.startswith('web/')

    def _get_access_path(self, node) -> List[Any]:
        if isinstance(node, ast.Name):
            return [self.aliases.get(node.id, node.id)]
        elif isinstance(node, ast.Attribute):
            parent_path = self._get_access_path(node.value)
            if parent_path:
                return parent_path + [node.attr]
        elif isinstance(node, ast.Subscript):
            parent_path = self._get_access_path(node.value)
            if parent_path:
                slice_val = self._resolve_expression(node.slice)
                if slice_val is not None:
                    return parent_path + [slice_val]
        return []

    def _get_path_taint(self, path: List[Any]) -> Optional[str]:
        if not path:
            return None
        # Fast-track environment variables
        if len(path) >= 2 and path[0] == 'os' and (path[1] == 'environ' or path[1] == 'getenv'):
            return 'env'
        if len(path) >= 3 and path[0] == 'os' and path[1] == 'environ' and path[2] == 'get':
            return 'env'
        if path[0] in ['environ', 'environ.get', 'os.environ.get']:
            return 'env'
            
        root = path[0]
        for scope in reversed(self.scopes):
            if root in scope:
                current = scope[root]
                for part in path[1:]:
                    parent_taint = current.get("taint")
                    if parent_taint and parent_taint not in ['mcp_sensitive_leak', 'mcp_param_leak', 'public_write_handle']:
                        return parent_taint
                    
                    sub_taints = current.get("sub_taints", {})
                    if part in sub_taints:
                        val = sub_taints[part]
                        if isinstance(val, dict):
                            current = val
                        else:
                            return val
                    else:
                        return parent_taint
                return current.get("taint")
        return None

    def _set_path_taint(self, path: List[Any], taint: Optional[str], value: Any = None):
        if not path:
            return
        root = path[0]
        target_scope = None
        for scope in reversed(self.scopes):
            if root in scope:
                target_scope = scope
                break
        if target_scope is None:
            target_scope = self.scopes[-1]
            target_scope[root] = {"value": None, "taint": None, "sub_taints": {}}
            
        current = target_scope[root]
        for part in path[1:]:
            if "sub_taints" not in current:
                current["sub_taints"] = {}
            if part not in current["sub_taints"]:
                current["sub_taints"][part] = {"value": None, "taint": None, "sub_taints": {}}
            elif isinstance(current["sub_taints"][part], str):
                current["sub_taints"][part] = {"value": None, "taint": current["sub_taints"][part], "sub_taints": {}}
            current = current["sub_taints"][part]
        
        current["taint"] = taint
        if value is not None:
            current["value"] = value

    def _contains_sensitive_constant(self, node) -> bool:
        class ConstantFinder(ast.NodeVisitor):
            def __init__(self, parent):
                self.parent = parent
                self.found = False
            def visit_Constant(self, c_node):
                if isinstance(c_node.value, str) and self.parent._is_sensitive_path(c_node.value):
                    self.found = True
        finder = ConstantFinder(self)
        finder.visit(node)
        return finder.found

    def _check_expression_for_taint(self, node) -> str:
        class TaintChecker(ast.NodeVisitor):
            def __init__(self, visitor_parent):
                self.parent = visitor_parent
                self.taint_found = None
                
            def visit_Name(self, name_node: ast.Name):
                access_path = self.parent._get_access_path(name_node)
                t = self.parent._get_path_taint(access_path)
                if t and t not in ['mcp_sensitive_leak', 'mcp_param_leak', 'public_write_handle']:
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

            def visit_Subscript(self, subscript_node: ast.Subscript):
                access_path = self.parent._get_access_path(subscript_node)
                t = self.parent._get_path_taint(access_path)
                if t and t not in ['mcp_sensitive_leak', 'mcp_param_leak', 'public_write_handle']:
                    self.taint_found = t
                    return
                self.generic_visit(subscript_node)

            def visit_Attribute(self, attr_node: ast.Attribute):
                resolved = self.parent._resolve_name(attr_node)
                if resolved in ['os.environ', 'os.getenv', 'environ'] or resolved.startswith('os.environ.') or resolved.startswith('environ.'):
                    self.taint_found = 'env'
                    return
                access_path = self.parent._get_access_path(attr_node)
                t = self.parent._get_path_taint(access_path)
                if t and t not in ['mcp_sensitive_leak', 'mcp_param_leak', 'public_write_handle']:
                    self.taint_found = t
                    return
                self.generic_visit(attr_node)
                
            def visit_Call(self, call_node: ast.Call):
                func_resolved = self.parent._resolve_name(call_node.func)
                if func_resolved in ['os.getenv', 'os.environ.get', 'environ.get'] or func_resolved.startswith('os.environ.') or func_resolved.startswith('environ.'):
                    self.taint_found = 'env'
                    return
                self.generic_visit(call_node)

            def visit_Constant(self, const_node: ast.Constant):
                if isinstance(const_node.value, str):
                    if is_metadata_ip_or_host(const_node.value):
                        self.taint_found = 'metadata_ssrf'
                        return
                    if has_high_entropy_token(const_node.value):
                        self.taint_found = 'high_entropy'
                        return
                    if self.parent._is_sensitive_name(const_node.value):
                        self.taint_found = 'sensitive'
                        return

        checker = TaintChecker(self)
        checker.visit(node)
        return checker.taint_found

    def _is_path_validated(self, node) -> bool:
        if not node:
            return False
        class NameCollector(ast.NodeVisitor):
            def __init__(self):
                self.names = []
            def visit_Call(self, c_node):
                for arg in c_node.args:
                    self.visit(arg)
                for kw in c_node.keywords:
                    self.visit(kw.value)
            def visit_Name(self, n):
                self.names.append(n.id)
                self.generic_visit(n)
        collector = NameCollector()
        collector.visit(node)
        if not collector.names:
            return False
        return all(name in self.validated_vars for name in collector.names)

    def _check_mcp_sensitive_read(self, node) -> str:
        if not isinstance(node, ast.Call):
            return None
        func_name = self._resolve_name(node.func)
        if func_name == 'open' and node.args:
            path_val = self._resolve_expression(node.args[0])
            if isinstance(path_val, str) and self._is_sensitive_path(path_val):
                return 'mcp_sensitive_leak'
            if self._contains_sensitive_constant(node.args[0]):
                return 'mcp_sensitive_leak'
            path_taint = self._check_expression_for_taint(node.args[0])
            if path_taint == 'mcp_param':
                if not self._is_path_validated(node.args[0]):
                    return 'mcp_param_leak'
        elif func_name.endswith('.read') or func_name.endswith('.read_text') or func_name.endswith('.read_bytes') or '.open().read' in func_name:
            if isinstance(node.func, ast.Attribute):
                caller_val = self._resolve_expression(node.func.value)
                if isinstance(caller_val, str) and self._is_sensitive_path(caller_val):
                    return 'mcp_sensitive_leak'
                if self._contains_sensitive_constant(node.func.value):
                    return 'mcp_sensitive_leak'
                path_taint = self._check_expression_for_taint(node.func.value)
                if path_taint == 'mcp_param':
                    if not self._is_path_validated(node.func.value):
                        return 'mcp_param_leak'
                elif isinstance(node.func.value, ast.Call):
                    sub_func = self._resolve_name(node.func.value.func)
                    if sub_func in ['open', 'Path', 'pathlib.Path'] and node.func.value.args:
                        sub_path = self._resolve_expression(node.func.value.args[0])
                        if isinstance(sub_path, str) and self._is_sensitive_path(sub_path):
                            return 'mcp_sensitive_leak'
                        if self._contains_sensitive_constant(node.func.value.args[0]):
                            return 'mcp_sensitive_leak'
        return None

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

    def _is_mcp_sensitive_expression(self, node) -> str:
        read_type = self._check_mcp_sensitive_read(node)
        if read_type:
            return read_type
            
        class MCPTaintChecker(ast.NodeVisitor):
            def __init__(self, visitor_parent):
                self.parent = visitor_parent
                self.leak_found = None
                
            def visit_Name(self, name_node: ast.Name):
                access_path = self.parent._get_access_path(name_node)
                t = self.parent._get_path_taint(access_path)
                if t in ['mcp_sensitive_leak', 'mcp_param_leak']:
                    self.leak_found = t
                    return
                        
            def visit_Call(self, call_node: ast.Call):
                read_type = self.parent._check_mcp_sensitive_read(call_node)
                if read_type:
                    self.leak_found = read_type
                    return
                self.generic_visit(call_node)

        checker = MCPTaintChecker(self)
        checker.visit(node)
        return checker.leak_found

    def _is_public_write_handle_var(self, node) -> bool:
        if isinstance(node, ast.Name):
            access_path = self._get_access_path(node)
            t = self._get_path_taint(access_path)
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
        
        old_validated = self.validated_vars.copy()
        
        if self.in_mcp_tool:
            for arg in node.args.args:
                self.scopes[-1][arg.arg] = {"value": None, "taint": 'mcp_param', "sub_taints": {}}
                
        self.generic_visit(node)
        self.scopes.pop()
        self.in_mcp_tool = old_mcp
        self.validated_vars = old_validated

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_With(self, node: ast.With):
        class NameCollector(ast.NodeVisitor):
            def __init__(self):
                self.names = []
            def visit_Name(self, n):
                self.names.append(n.id)
                self.generic_visit(n)
        collector = NameCollector()
        for item in node.items:
            mcp_read = self._check_mcp_sensitive_read(item.context_expr)
            if mcp_read:
                if isinstance(item.optional_vars, ast.Name):
                    self.scopes[-1][item.optional_vars.id] = {"value": None, "taint": mcp_read, "sub_taints": {}}
            elif self._check_public_write_handle(item.context_expr):
                if isinstance(item.optional_vars, ast.Name):
                    self.scopes[-1][item.optional_vars.id] = {"value": None, "taint": 'public_write_handle', "sub_taints": {}}
            if item.optional_vars:
                collector.visit(item.optional_vars)
        for name in collector.names:
            if name in self.validated_vars:
                self.validated_vars.remove(name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        taint = None
        val = self._resolve_expression(node.value)
        
        mcp_expr_taint = self._is_mcp_sensitive_expression(node.value)
        
        if self._check_mcp_sensitive_read(node.value):
            taint = self._check_mcp_sensitive_read(node.value)
        elif self._check_public_write_handle(node.value):
            taint = 'public_write_handle'
        elif mcp_expr_taint:
            taint = mcp_expr_taint
        else:
            if isinstance(val, str):
                if val in ['os.environ', 'os.getenv', 'environ'] or val.startswith('os.environ.') or val.startswith('environ.'):
                    taint = 'env'
                elif self._is_sensitive_name(val):
                    taint = 'sensitive'
                elif has_high_entropy_token(val):
                    taint = 'high_entropy'
                elif is_metadata_ip_or_host(val):
                    taint = 'metadata_ssrf'

            if not taint:
                taint = self._check_expression_for_taint(node.value)

        # Clear validation status for assigned targets (TOCTOU mitigation)
        class NameCollector(ast.NodeVisitor):
            def __init__(self):
                self.names = []
            def visit_Name(self, n):
                self.names.append(n.id)
                self.generic_visit(n)
        collector = NameCollector()
        for target in node.targets:
            collector.visit(target)
        for name in collector.names:
            if name in self.validated_vars:
                self.validated_vars.remove(name)

        for target in node.targets:
            access_path = self._get_access_path(target)
            if access_path:
                self._set_path_taint(access_path, taint, val)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        if isinstance(node.target, ast.Name):
            if node.target.id in self.validated_vars:
                self.validated_vars.remove(node.target.id)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        class NameCollector(ast.NodeVisitor):
            def __init__(self):
                self.names = []
            def visit_Name(self, n):
                self.names.append(n.id)
                self.generic_visit(n)
        collector = NameCollector()
        collector.visit(node.target)
        for name in collector.names:
            if name in self.validated_vars:
                self.validated_vars.remove(name)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if self.in_mcp_tool and node.value:
            taint = self._check_expression_for_taint(node.value)
            mcp_taint = self._is_mcp_sensitive_expression(node.value)
            
            leak_type = taint if taint in ['metadata_ssrf', 'mcp_param_leak', 'mcp_sensitive_leak'] else mcp_taint
            
            if leak_type == 'mcp_sensitive_leak':
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "AI Data Exfiltration: MCP Tool File Leakage",
                    "severity": "CRITICAL",
                    "message": "MCP tool returns sensitive file content directly to LLM context.",
                    "suggestion": "Do not return raw sensitive file content in MCP tools. Parse, filter, or restrict tool access."
                })
            elif leak_type == 'mcp_param_leak':
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "AI Data Exfiltration: MCP Tool Parameter Arbitrary File Leakage",
                    "severity": "HIGH",
                    "message": "MCP tool reads and returns file content from an unvalidated parameter path, leading to arbitrary file leakage.",
                    "suggestion": "Validate the parameter path before reading. Ensure it does not escape the workspace directory."
                })
            elif leak_type == 'metadata_ssrf':
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "AI Data Exfiltration: Metadata API SSRF Leakage",
                    "severity": "CRITICAL",
                    "message": "MCP tool returns cloud metadata endpoint directly to LLM context.",
                    "suggestion": "Do not return cloud metadata service URLs or credentials in MCP tools."
                })
        self.generic_visit(node)

    def _is_llm_api(self, name: str) -> bool:
        parts = name.split('.')
        return any(x in parts for x in ['completions', 'messages', 'invoke', 'generateContent'])

    def visit_If(self, node: ast.If):
        old_val = self.in_validation_context
        self.in_validation_context = True
        self.visit(node.test)
        self.in_validation_context = False
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        self.in_validation_context = old_val

    def visit_While(self, node: ast.While):
        old_val = self.in_validation_context
        self.in_validation_context = True
        self.visit(node.test)
        self.in_validation_context = False
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        self.in_validation_context = old_val

    def visit_Assert(self, node: ast.Assert):
        old_val = self.in_validation_context
        self.in_validation_context = True
        self.visit(node.test)
        self.in_validation_context = False
        if node.msg:
            self.visit(node.msg)
        self.in_validation_context = old_val

    def visit_Expr(self, node: ast.Expr):
        if isinstance(node.value, ast.Call):
            func_name_short = ""
            if isinstance(node.value.func, ast.Name):
                func_name_short = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                func_name_short = node.value.func.attr
            if func_name_short == 'validate_path':
                old_val = self.in_validation_context
                self.in_validation_context = True
                self.visit(node.value)
                self.in_validation_context = old_val
                return
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        if self.in_validation_context:
            var_name = None
            has_dots = False
            if isinstance(node.left, ast.Constant) and node.left.value == '..':
                has_dots = True
            elif isinstance(node.left, ast.Name):
                var_name = node.left.id
            for op in node.comparators:
                if isinstance(op, ast.Constant) and op.value == '..':
                    has_dots = True
                elif isinstance(op, ast.Name):
                    var_name = op.id
            if has_dots and var_name:
                self.validated_vars.add(var_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if self.in_validation_context:
            func_name_short = ""
            if isinstance(node.func, ast.Name):
                func_name_short = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name_short = node.func.attr
            if func_name_short in ['is_relative_to', 'is_safe', 'validate_path']:
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        self.validated_vars.add(arg.id)
                    elif isinstance(arg, ast.Call):
                        if isinstance(arg.func, ast.Attribute) and isinstance(arg.func.value, ast.Name):
                            self.validated_vars.add(arg.func.value.id)
                if isinstance(node.func, ast.Attribute):
                    class NameVisitor(ast.NodeVisitor):
                        def __init__(self, names_set):
                            self.names_set = names_set
                        def visit_Name(self, n):
                            self.names_set.add(n.id)
                            self.generic_visit(n)
                    NameVisitor(self.validated_vars).visit(node.func.value)

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

        # Shutil copyfile / copy / move / copy2 / copytree
        elif func_name in ['shutil.copy', 'shutil.copyfile', 'shutil.move', 'shutil.copy2', 'shutil.copytree', 'copy', 'copyfile', 'move'] and len(node.args) >= 2:
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

        # OS rename / replace
        elif func_name in ['os.rename', 'os.replace', 'rename', 'replace'] and len(node.args) >= 2:
            src_val = self._resolve_expression(node.args[0])
            dst_val = self._resolve_expression(node.args[1])
            if isinstance(src_val, str) and self._is_sensitive_path(src_val):
                if isinstance(dst_val, str) and self._is_public_directory(dst_val):
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "AI Data Exfiltration: Public Output Leakage",
                        "severity": "MEDIUM",
                        "message": "Potential sensitive file moved to a public web directory.",
                        "suggestion": "Avoid moving sensitive files like .env or id_rsa to public web directories."
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


class JsValidationScanner:
    def __init__(self):
        self.validated_names = set()

    def walk(self, node):
        if not node:
            return
        node_type = getattr(node, 'type', '')
        
        # Check CallExpression: path.includes('..') or path.indexOf('..')
        if node_type == 'CallExpression':
            callee = getattr(node, 'callee', None)
            arguments = getattr(node, 'arguments', [])
            if callee and getattr(callee, 'type', '') == 'MemberExpression':
                obj = getattr(callee, 'object', None)
                prop = getattr(callee, 'property', None)
                if obj and prop and getattr(obj, 'type', '') == 'Identifier' and getattr(prop, 'type', '') == 'Identifier':
                    var_name = getattr(obj, 'name', '')
                    method_name = getattr(prop, 'name', '')
                    if method_name in ['includes', 'indexOf'] and arguments:
                        arg0 = arguments[0]
                        if getattr(arg0, 'type', '') == 'Literal' and getattr(arg0, 'value', '') == '..':
                            self.validated_names.add(var_name)
                            
        # Check BinaryExpression: path === '..' or '..' === path
        elif node_type == 'BinaryExpression':
            operator = getattr(node, 'operator', '')
            if operator in ['==', '===', '!=', '!==']:
                left = getattr(node, 'left', None)
                right = getattr(node, 'right', None)
                var_name = None
                has_dots = False
                if left and getattr(left, 'type', '') == 'Identifier':
                    var_name = getattr(left, 'name', '')
                elif left and getattr(left, 'type', '') == 'Literal' and getattr(left, 'value', '') == '..':
                    has_dots = True
                
                if right and getattr(right, 'type', '') == 'Identifier':
                    var_name = getattr(right, 'name', '')
                elif right and getattr(right, 'type', '') == 'Literal' and getattr(right, 'value', '') == '..':
                    has_dots = True
                    
                if has_dots and var_name:
                    self.validated_names.add(var_name)

        # Recursively walk child nodes
        for key, value in getattr(node, '__dict__', {}).items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.walk(item)
            elif hasattr(value, 'type'):
                self.walk(value)


class JsDataExfiltrationVisitor:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.scopes = [{}]
        self.in_mcp_tool = False
        self.validated_vars = set()
        self.in_validation_context = False
        file_lower = os.path.basename(file_path).lower()
        self.has_mcp = 'mcp' in file_lower or 'tool' in file_lower

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
        elif n_type == 'TemplateLiteral':
            parts = []
            quasis = getattr(node, 'quasis', [])
            exprs = getattr(node, 'expressions', [])
            for i, quasi in enumerate(quasis):
                val_obj = getattr(quasi, 'value', None)
                cooked = getattr(val_obj, 'cooked', '') if val_obj else ''
                parts.append(cooked)
                if i < len(exprs):
                    resolved_expr = self._resolve_expression(exprs[i])
                    if resolved_expr:
                        parts.append(resolved_expr)
                    else:
                        parts.append("{}")
            return "".join(parts)
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
        elif n_type == 'CallExpression':
            callee = getattr(node, 'callee', None)
            if callee and getattr(callee, 'type', '') == 'Identifier' and getattr(callee, 'name', '') == 'require':
                args = getattr(node, 'arguments', [])
                if args and getattr(args[0], 'type', '') == 'Literal':
                    return getattr(args[0], 'value', '')
        return ""

    def _resolve_name(self, node) -> str:
        if not node:
            return ""
        n_type = getattr(node, 'type', '')
        if n_type == 'Identifier':
            var_name = getattr(node, 'name', '')
            for scope in reversed(self.scopes):
                if var_name in scope:
                    t = scope[var_name].get("taint")
                    if t:
                        return t
                    val = scope[var_name].get("value")
                    if val is not None:
                        return val
            return var_name
        elif n_type == 'MemberExpression':
            obj_str = self._resolve_name(node.object)
            prop_str = self._resolve_name(node.property)
            if obj_str and prop_str:
                return f"{obj_str}.{prop_str}"
            return prop_str or obj_str
        elif n_type == 'TemplateLiteral':
            return self._resolve_expression(node)
        elif n_type == 'CallExpression':
            callee = getattr(node, 'callee', None)
            if callee and getattr(callee, 'type', '') == 'Identifier' and getattr(callee, 'name', '') == 'require':
                args = getattr(node, 'arguments', [])
                if args and getattr(args[0], 'type', '') == 'Literal':
                    return getattr(args[0], 'value', '')
        return ""

    def _is_sensitive_path(self, path: str) -> bool:
        path = path.lower()
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
        path = path.lower()
        normalized = path.replace('\\', '/')
        public_dirs = ['public/', 'dist/', 'static/', 'assets/', 'web/']
        return any(pub in normalized for pub in public_dirs) or normalized.startswith('public/') or normalized.startswith('dist/') or normalized.startswith('static/') or normalized.startswith('assets/') or normalized.startswith('web/')

    def _is_path_validated(self, node) -> bool:
        if not node:
            return False
        names = []
        def collect(n):
            if not n:
                return
            n_type = getattr(n, 'type', '')
            if n_type == 'Identifier':
                names.append(getattr(n, 'name', ''))
            for key, value in getattr(n, '__dict__', {}).items():
                if isinstance(value, list):
                    for item in value:
                        if hasattr(item, 'type'):
                            collect(item)
                elif hasattr(value, 'type'):
                    collect(value)
        collect(node)
        if not names:
            return False
        return all(name in self.validated_vars for name in names)

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
                base_str = self._resolve_name(n.object)
                prop_str = self._resolve_expression(n.property)
                if base_str and prop_str:
                    for scope in reversed(self.scopes):
                        if base_str in scope:
                            if scope[base_str].get("sub_taints", {}).get(prop_str):
                                found_taint[0] = scope[base_str]["sub_taints"][prop_str]
                                return
                            base_taint = scope[base_str].get("taint")
                            if base_taint:
                                found_taint[0] = base_taint
                                return
            elif n_type == 'CallExpression':
                callee_str = self._resolve_expression(n)
                resolved_callee = self._resolve_name(n.callee)
                if (resolved_callee in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile'] or 
                    callee_str in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile']) and getattr(n, 'arguments', None):
                    path_val = self._resolve_expression(n.arguments[0])
                    if isinstance(path_val, str) and self._is_sensitive_path(path_val):
                        found_taint[0] = 'mcp_sensitive_leak'
                        return
                    path_taint = self._check_expression_for_taint(n.arguments[0])
                    if path_taint == 'mcp_param':
                        if not self._is_path_validated(n.arguments[0]):
                            found_taint[0] = 'mcp_param_leak'
                            return
            elif n_type == 'TemplateLiteral':
                for quasi in getattr(n, 'quasis', []) or []:
                    walk_node(quasi)
                for expr in getattr(n, 'expressions', []) or []:
                    walk_node(expr)
            elif n_type == 'Literal':
                val = getattr(n, 'value', None)
                if isinstance(val, str):
                    if is_metadata_ip_or_host(val):
                        found_taint[0] = 'metadata_ssrf'
                        return
                    if has_high_entropy_token(val):
                        found_taint[0] = 'high_entropy'
                        return
                    if any(k in val.lower() for k in ['api_key', 'secret', 'password', 'token', 'private_key']):
                        found_taint[0] = 'sensitive'
                        return

            for key, value in getattr(n, '__dict__', {}).items():
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

        # Handle validation context control flow
        if node_type == 'IfStatement':
            old_val = self.in_validation_context
            self.in_validation_context = True
            self.walk(getattr(node, 'test', None))
            self.in_validation_context = False
            self.walk(getattr(node, 'consequent', None))
            self.walk(getattr(node, 'alternate', None))
            self.in_validation_context = old_val
            return
            
        if node_type in ['WhileStatement', 'DoWhileStatement']:
            old_val = self.in_validation_context
            self.in_validation_context = True
            self.walk(getattr(node, 'test', None))
            self.in_validation_context = False
            self.walk(getattr(node, 'body', None))
            self.in_validation_context = old_val
            return
            
        if node_type == 'ConditionalExpression':
            old_val = self.in_validation_context
            self.in_validation_context = True
            self.walk(getattr(node, 'test', None))
            self.in_validation_context = False
            self.walk(getattr(node, 'consequent', None))
            self.walk(getattr(node, 'alternate', None))
            self.in_validation_context = old_val
            return
            
        if node_type == 'ExpressionStatement':
            expr = getattr(node, 'expression', None)
            if expr and getattr(expr, 'type', '') == 'CallExpression':
                callee = getattr(expr, 'callee', None)
                if callee and getattr(callee, 'type', '') == 'Identifier':
                    func_name = getattr(callee, 'name', '')
                    if func_name == 'validate_path':
                        old_val = self.in_validation_context
                        self.in_validation_context = True
                        self.walk(expr)
                        self.in_validation_context = old_val
                        return
        
        is_function = node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']
        is_class = node_type in ['ClassDeclaration', 'ClassExpression']

        if is_function:
            old_mcp = self.in_mcp_tool
            if self.has_mcp:
                self.in_mcp_tool = True
            self.push_scope()
            
            old_validated = self.validated_vars.copy()
            
            if self.in_mcp_tool:
                for param in getattr(node, 'params', []) or []:
                    p_type = getattr(param, 'type', '')
                    if p_type == 'Identifier':
                        p_name = getattr(param, 'name', '')
                        if p_name:
                            self.scopes[-1][p_name] = {"value": None, "taint": 'mcp_param', "sub_taints": {}}
                    elif p_type == 'ObjectPattern':
                        for prop in getattr(param, 'properties', []) or []:
                            prop_val = getattr(prop, 'value', None)
                            if prop_val and getattr(prop_val, 'type', '') == 'Identifier':
                                p_name = getattr(prop_val, 'name', '')
                                if p_name:
                                    self.scopes[-1][p_name] = {"value": None, "taint": 'mcp_param', "sub_taints": {}}
        elif is_class:
            self.push_scope()

        if node_type == 'VariableDeclarator':
            init_val = getattr(node, 'init', None)
            id_node = getattr(node, 'id', None)
            id_type = getattr(id_node, 'type', '') if id_node else ''
            
            # Clear validation (TOCTOU mitigation)
            if id_node:
                if id_type == 'Identifier':
                    name = getattr(id_node, 'name', '')
                    if name in self.validated_vars:
                        self.validated_vars.remove(name)
                elif id_type == 'ObjectPattern':
                    for prop in getattr(id_node, 'properties', []) or []:
                        prop_val = getattr(prop, 'value', None)
                        if prop_val and getattr(prop_val, 'type', '') == 'Identifier':
                            name = getattr(prop_val, 'name', '')
                            if name in self.validated_vars:
                                self.validated_vars.remove(name)
            
            if init_val:
                val = self._resolve_expression(init_val)
                taint = None
                init_str = self._resolve_expression(init_val)
                if isinstance(init_str, str) and init_str.startswith('process.env'):
                    taint = 'env'
                elif isinstance(init_str, str) and self._is_sensitive_path(init_str):
                    taint = 'mcp_sensitive_leak'
                elif isinstance(init_str, str) and is_metadata_ip_or_host(init_str):
                    taint = 'metadata_ssrf'
                else:
                    taint = self._check_expression_for_taint(init_val)
                
                # Check for require('fs') destructuring
                if init_str == 'fs' and id_type == 'ObjectPattern':
                    for prop in getattr(id_node, 'properties', []) or []:
                        prop_key = getattr(getattr(prop, 'key', None), 'name', '')
                        prop_val = getattr(getattr(prop, 'value', None), 'name', '')
                        if prop_key and prop_val:
                            self.scopes[-1][prop_val] = {"value": f"fs.{prop_key}", "taint": None, "sub_taints": {}}
                elif id_type == 'Identifier':
                    id_name = getattr(id_node, 'name', '')
                    if id_name:
                        self.scopes[-1][id_name] = {"value": val, "taint": taint, "sub_taints": {}}

        elif node_type == 'AssignmentExpression':
            left = getattr(node, 'left', None)
            if left:
                left_type = getattr(left, 'type', '')
                if left_type == 'Identifier':
                    name = getattr(left, 'name', '')
                    if name in self.validated_vars:
                        self.validated_vars.remove(name)
                elif left_type == 'MemberExpression':
                    obj = getattr(left, 'object', None)
                    if obj and getattr(obj, 'type', '') == 'Identifier':
                        name = getattr(obj, 'name', '')
                        if name in self.validated_vars:
                            self.validated_vars.remove(name)

            left_str = self._resolve_name(node.left)
            is_member = getattr(node.left, 'type', '') == 'MemberExpression'
            if left_str:
                val = self._resolve_expression(node.right)
                taint = None
                right_str = self._resolve_expression(node.right)
                if isinstance(right_str, str) and right_str.startswith('process.env'):
                    taint = 'env'
                elif isinstance(right_str, str) and self._is_sensitive_path(right_str):
                    taint = 'mcp_sensitive_leak'
                elif isinstance(right_str, str) and is_metadata_ip_or_host(right_str):
                    taint = 'metadata_ssrf'
                else:
                    taint = self._check_expression_for_taint(node.right)
                
                if is_member:
                    base_str = self._resolve_name(node.left.object)
                    prop_str = self._resolve_expression(node.left.property)
                    if base_str and prop_str:
                        found = False
                        for scope in reversed(self.scopes):
                            if base_str in scope:
                                if "sub_taints" not in scope[base_str]:
                                    scope[base_str]["sub_taints"] = {}
                                scope[base_str]["sub_taints"][prop_str] = taint
                                found = True
                                break
                        if not found:
                            self.scopes[-1][base_str] = {"value": {}, "taint": None, "sub_taints": {prop_str: taint}}
                else:
                    self.scopes[-1][left_str] = {"value": val, "taint": taint, "sub_taints": {}}

        elif node_type == 'ImportDeclaration':
            source = getattr(getattr(node, 'source', None), 'value', '')
            if 'mcp' in source or 'fastmcp' in source:
                self.has_mcp = True
            
            # Map imports
            for spec in getattr(node, 'specifiers', []) or []:
                spec_type = getattr(spec, 'type', '')
                local_name = getattr(getattr(spec, 'local', None), 'name', '')
                if spec_type in ['ImportDefaultSpecifier', 'ImportNamespaceSpecifier']:
                    if source == 'fs':
                        self.scopes[-1][local_name] = {"value": "fs", "taint": None, "sub_taints": {}}
                elif spec_type == 'ImportSpecifier':
                    imported_name = getattr(getattr(spec, 'imported', None), 'name', '')
                    if source == 'fs' and local_name and imported_name:
                        self.scopes[-1][local_name] = {"value": f"fs.{imported_name}", "taint": None, "sub_taints": {}}

        elif node_type == 'BinaryExpression':
            if self.in_validation_context:
                operator = getattr(node, 'operator', '')
                if operator in ['==', '===', '!=', '!==']:
                    left = getattr(node, 'left', None)
                    right = getattr(node, 'right', None)
                    var_name = None
                    has_dots = False
                    if left and getattr(left, 'type', '') == 'Identifier':
                        var_name = getattr(left, 'name', '')
                    elif left and getattr(left, 'type', '') == 'Literal' and getattr(left, 'value', '') == '..':
                        has_dots = True
                    
                    if right and getattr(right, 'type', '') == 'Identifier':
                        var_name = getattr(right, 'name', '')
                    elif right and getattr(right, 'type', '') == 'Literal' and getattr(right, 'value', '') == '..':
                        has_dots = True
                        
                    if has_dots and var_name:
                        self.validated_vars.add(var_name)

        elif node_type == 'CallExpression':
            if self.in_validation_context:
                callee = getattr(node, 'callee', None)
                arguments = getattr(node, 'arguments', [])
                if callee and getattr(callee, 'type', '') == 'MemberExpression':
                    obj = getattr(callee, 'object', None)
                    prop = getattr(callee, 'property', None)
                    if obj and prop and getattr(obj, 'type', '') == 'Identifier' and getattr(prop, 'type', '') == 'Identifier':
                        var_name = getattr(obj, 'name', '')
                        method_name = getattr(prop, 'name', '')
                        if method_name in ['includes', 'indexOf'] and arguments:
                            arg0 = arguments[0]
                            if getattr(arg0, 'type', '') == 'Literal' and getattr(arg0, 'value', '') == '..':
                                self.validated_vars.add(var_name)
                elif callee and getattr(callee, 'type', '') == 'Identifier':
                    func_name = getattr(callee, 'name', '')
                    if func_name in ['is_safe', 'validate_path', 'is_relative_to']:
                        for arg in arguments:
                            if getattr(arg, 'type', '') == 'Identifier':
                                self.validated_vars.add(getattr(arg, 'name', ''))

            callee_str = self._resolve_expression(node.callee)
            resolved_callee = self._resolve_name(node.callee)
            
            if callee_str == 'require' and node.arguments:
                arg_val = self._resolve_expression(node.arguments[0])
                if isinstance(arg_val, str) and ('mcp' in arg_val or 'fastmcp' in arg_val):
                    self.has_mcp = True
            
            is_llm = False
            if any(x in callee_str or x in resolved_callee for x in ['completions', 'messages', 'invoke', 'generateContent']):
                is_llm = True
            
            if is_llm:
                for arg in getattr(node, 'arguments', []):
                    taint = self._check_expression_for_taint(arg)
                    if taint:
                        is_ssrf = (taint == 'metadata_ssrf')
                        name = "AI Data Exfiltration: Metadata API SSRF Leakage" if is_ssrf else "AI Data Exfiltration: LLM Prompt Leakage"
                        msg = f"Potential SSRF exfiltration of cloud metadata API to LLM API call '{callee_str}'." if is_ssrf else f"Potential sensitive data exfiltration to LLM API call '{callee_str}' via tainted prompt argument."
                        self.findings.append({
                            "file": self.file_path,
                            "line": line,
                            "name": name,
                            "severity": "HIGH",
                            "message": msg,
                            "suggestion": "Do not pass cloud metadata service URLs or credentials to external LLMs. Ensure user input and tool outputs are properly sanitized."
                        })

            is_sensitive_read = False
            if (resolved_callee in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile'] or 
                callee_str in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile']) and node.arguments:
                path_val = self._resolve_expression(node.arguments[0])
                if isinstance(path_val, str) and self._is_sensitive_path(path_val):
                    is_sensitive_read = True

            if (resolved_callee in ['fs.writeFileSync', 'fs.writeFile', 'fs.createWriteStream'] or 
                callee_str in ['fs.writeFileSync', 'fs.writeFile', 'fs.createWriteStream']) and node.arguments:
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

            # Copy and move checks for JS
            if (resolved_callee in [
                'fs.copyFileSync', 'fs.copyFile', 'fs.promises.copyFile',
                'fs.renameSync', 'fs.rename', 'fs.promises.rename'
            ] or callee_str in [
                'fs.copyFileSync', 'fs.copyFile', 'fs.promises.copyFile',
                'fs.renameSync', 'fs.rename', 'fs.promises.rename'
            ]) and len(node.arguments) >= 2:
                src_val = self._resolve_expression(node.arguments[0])
                dst_val = self._resolve_expression(node.arguments[1])
                if isinstance(src_val, str) and self._is_sensitive_path(src_val):
                    if isinstance(dst_val, str) and self._is_public_directory(dst_val):
                        is_rename = 'rename' in (resolved_callee or callee_str)
                        name = "AI Data Exfiltration: Public Output Leakage"
                        msg = ("Potential sensitive file moved to a public web directory." if is_rename 
                               else "Potential sensitive file copied to a public web directory.")
                        self.findings.append({
                            "file": self.file_path,
                            "line": line,
                            "name": name,
                            "severity": "MEDIUM",
                            "message": msg,
                            "suggestion": "Avoid copying or moving sensitive files like .env or id_rsa to public web directories."
                        })

        elif node_type == 'ReturnStatement' and node.argument:
            if self.in_mcp_tool:
                taint = self._check_expression_for_taint(node.argument)
                is_leak = False
                is_param_leak = False
                if taint == 'mcp_sensitive_leak':
                    is_leak = True
                elif taint == 'mcp_param_leak':
                    is_param_leak = True
                elif taint == 'metadata_ssrf':
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "AI Data Exfiltration: Metadata API SSRF Leakage",
                        "severity": "CRITICAL",
                        "message": "MCP tool returns cloud metadata endpoint directly to LLM context.",
                        "suggestion": "Do not return cloud metadata service URLs or credentials in MCP tools."
                    })
                else:
                    arg_type = getattr(node.argument, 'type', '')
                    if arg_type == 'CallExpression':
                        callee_str = self._resolve_expression(node.argument.callee)
                        resolved_callee = self._resolve_name(node.argument.callee)
                        if (resolved_callee in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile'] or 
                            callee_str in ['fs.readFileSync', 'fs.readFile', 'fs.promises.readFile']) and getattr(node.argument, 'arguments', None):
                            path_val = self._resolve_expression(node.argument.arguments[0])
                            if isinstance(path_val, str) and self._is_sensitive_path(path_val):
                                is_leak = True
                            else:
                                path_taint = self._check_expression_for_taint(node.argument.arguments[0])
                                if path_taint == 'mcp_param':
                                    if not self._is_path_validated(node.argument.arguments[0]):
                                        is_param_leak = True
                
                if is_leak:
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "AI Data Exfiltration: MCP Tool File Leakage",
                        "severity": "CRITICAL",
                        "message": "MCP tool returns sensitive file content directly to LLM context.",
                        "suggestion": "Do not return raw sensitive file content in MCP tools. Parse, filter, or restrict tool access."
                    })
                elif is_param_leak:
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "AI Data Exfiltration: MCP Tool Parameter Arbitrary File Leakage",
                        "severity": "HIGH",
                        "message": "MCP tool reads and returns file content from an unvalidated parameter path, leading to arbitrary file leakage.",
                        "suggestion": "Validate the parameter path before reading. Ensure it does not escape the workspace directory."
                    })

        for key, value in getattr(node, '__dict__', {}).items():
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
                self.validated_vars = old_validated


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
        path = path.lower()
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
        path = path.lower()
        normalized = path.replace('\\', '/')
        public_dirs = ['public/', 'dist/', 'static/', 'assets/', 'web/']
        return any(pub in normalized for pub in public_dirs) or normalized.startswith('public/') or normalized.startswith('dist/') or normalized.startswith('static/') or normalized.startswith('assets/') or normalized.startswith('web/')

    def scan_text(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        file_lower = os.path.basename(file_path).lower()
        has_mcp_import = any(x in content for x in ['import mcp', 'require("mcp")', "require('mcp')", 'fastmcp']) or 'mcp' in file_lower or 'tool' in file_lower
        tainted_vars = set()
        metadata_vars = set()

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
                is_metadata = False
                if any(x in right_side for x in ['os.environ', 'process.env', 'os.getenv', 'environ.get']):
                    is_tainted = True
                elif has_high_entropy_token(right_side):
                    is_tainted = True
                elif self._is_sensitive_name(var_name):
                    is_tainted = True
                elif is_metadata_ip_or_host(right_side):
                    is_metadata = True
                
                if is_tainted:
                    tainted_vars.add(var_name)
                if is_metadata:
                    metadata_vars.add(var_name)

        # Pass 2: Match LLM calls and extract full parenthesized arguments list
        llm_api_pat = re.compile(r'\b(completions\.create|messages\.create|invoke|generateContent)\b')
        for m in llm_api_pat.finditer(content):
            api_name = m.group(1)
            start_idx = m.start()
            line_num = content[:start_idx].count('\n') + 1

            # Extract the parenthesized block starting after the match
            args_content = ""
            open_paren_idx = content.find('(', m.end())
            if open_paren_idx != -1:
                # Ensure there is only whitespace between the api name and '('
                between = content[m.end():open_paren_idx]
                if between.strip() == "":
                    # Walk to extract the full block balancing parentheses
                    depth = 1
                    i = open_paren_idx + 1
                    while i < len(content) and depth > 0:
                        char = content[i]
                        if char == '(':
                            depth += 1
                        elif char == ')':
                            depth -= 1
                        i += 1
                    if depth == 0:
                        args_content = content[open_paren_idx + 1 : i - 1]
                    else:
                        args_content = content[open_paren_idx + 1 :]

            if args_content:
                is_ssrf = is_metadata_ip_or_host(args_content) or any(v in args_content for v in metadata_vars)
                has_leak = is_ssrf or any(x in args_content for x in ['os.environ', 'process.env', 'os.getenv', 'environ.get']) or any(v in args_content for v in tainted_vars) or any(self._is_sensitive_name(token) for token in re.split(r'\W+', args_content)) or has_high_entropy_token(args_content)

                if has_leak:
                    name = "AI Data Exfiltration: Metadata API SSRF Leakage" if is_ssrf else "AI Data Exfiltration: LLM Prompt Leakage"
                    msg = f"Potential SSRF exfiltration of cloud metadata API to LLM API call '{api_name}' detected via text scan." if is_ssrf else f"Potential sensitive data exfiltration to LLM API call '{api_name}' detected via text scan."
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": name,
                        "severity": "HIGH",
                        "message": msg,
                        "suggestion": "Do not pass cloud metadata service URLs or credentials to external LLMs. Ensure user input and tool outputs are properly sanitized."
                    })

        # Pass 3: Simple line-level fallback for reading sensitive files in files that use MCP
        for i, line in enumerate(lines):
            line_num = i + 1
            line_lower = line.lower()
            trimmed = line.strip()
            if trimmed.startswith('#') or trimmed.startswith('//') or trimmed.startswith('*'):
                continue

            if has_mcp_import:
                is_ssrf = is_metadata_ip_or_host(line_lower)
                is_sensitive_read = any(x in line_lower for x in ['open(', 'readfilesync', 'readfile', 'read_text', 'read_bytes']) and self._is_sensitive_path(line_lower)
                if is_ssrf or is_sensitive_read:
                    name = "AI Data Exfiltration: Metadata API SSRF Leakage" if is_ssrf else "AI Data Exfiltration: MCP Tool File Leakage"
                    msg = "Potential MCP tool cloud metadata read detected via text scan." if is_ssrf else "Potential MCP tool sensitive file read detected via text scan."
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": name,
                        "severity": "CRITICAL",
                        "message": msg,
                        "suggestion": "Do not return raw sensitive file content or metadata endpoints in MCP tools. Parse, filter, or restrict tool access."
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
