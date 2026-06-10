import ast
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

try:
    import esprima
except ImportError:
    esprima = None

class LethalTrifectaDetector(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "lethaltrifectadetector"

    @property
    def description(self) -> str:
        return "Detects dangerous co-occurrence of Private Data Access, Untrusted Input, and Tool/Command Execution inside agent scopes"

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        for file_path in files:
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.py':
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Fast pre-filtering: check if file has any core capability indicators
                    prefilter_keywords = [
                        'subprocess', 'system', 'popen', 'exec', 'eval', 'importlib', 'tool', 'mcp_tool',
                        'open', 'sqlite3', 'MongoClient', 'getenv', 'environ', 'shutil', 'listdir',
                        'input', 'get_json', 'form.get', 'query', 'search', 'retrieve', 'request', 'argv',
                        'posix', 'ctypes', 'pathlib', 'urllib', 'read_text', 'read_bytes', 'walk', 'create_engine',
                        'check_output', 'check_call', 'spawn', 'fork', 'startfile', 'linecache', 'fileinput',
                        'socket', 'aiohttp'
                    ]
                    if not any(kw in content for kw in prefilter_keywords):
                        continue

                    tree = ast.parse(content, filename=file_path)
                    visitor = TrifectaVisitor(file_path)
                    visitor.visit(tree)
                    findings.extend(visitor.findings)

                except Exception:
                    pass
            elif ext in ['.js', '.ts', '.jsx', '.tsx'] and esprima is not None:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Fast pre-filtering for JS/TS
                    prefilter_keywords = [
                        'exec', 'spawn', 'eval', 'Function', 'require', 'import',
                        'fs', 'readFile', 'readFileSync', 'process.env', 'connect', 'MongoClient',
                        'process.argv', 'readline', 'prompt', 'query', 'body', 'params', 'headers'
                    ]
                    if not any(kw in content for kw in prefilter_keywords):
                        continue

                    try:
                        tree = esprima.parseModule(content, loc=True)
                    except Exception:
                        tree = esprima.parseScript(content, loc=True)

                    visitor = JsTrifectaVisitor(file_path)
                    visitor.walk(tree)
                    
                    # Evaluate global scope
                    if visitor.scopes:
                        global_scope = visitor.pop_scope()
                        visitor.evaluate_scope(global_scope, 1)
                        
                    findings.extend(visitor.findings)
                except Exception:
                    pass
        return findings



class TrifectaVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        
        # Import alias mapping
        self.aliases = {}
        
        # Stack of scopes. Each scope is a dict tracking detected capabilities
        # and their line numbers.
        self.scopes = []
        # Push global scope
        self.push_scope("global")
        # Track reported combinations of line numbers to avoid duplicate alerts in nested scopes
        self.reported_combinations = []

    def push_scope(self, name: str):
        self.scopes.append({
            "name": name,
            "private_data": [],      # list of (line, detail)
            "untrusted_input": [],   # list of (line, detail)
            "command_exec": []       # list of (line, detail)
        })

    def pop_scope(self) -> Dict[str, Any]:
        return self.scopes.pop()

    def add_capability(self, cap_type: str, line: int, detail: str):
        if self.scopes:
            self.scopes[-1][cap_type].append((line, detail))

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

    def _get_full_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            val_name = self._get_full_name(node.value)
            if val_name:
                resolved_val = self.aliases.get(val_name, val_name)
                return f"{resolved_val}.{node.attr}"
        return ""

    def visit_ClassDef(self, node: ast.ClassDef):
        self.push_scope(f"class:{node.name}")
        self.generic_visit(node)
        scope_data = self.pop_scope()
        self.evaluate_scope(scope_data, node.lineno)

    def _process_function(self, node):
        self.push_scope(f"function:{node.name}")
        
        # Check decorators first
        is_decorated = False
        for dec in node.decorator_list:
            dec_name = self._get_full_name(dec)
            if not dec_name and isinstance(dec, ast.Call):
                dec_name = self._get_full_name(dec.func)
            
            if dec_name:
                dec_lower = dec_name.lower()
                # Check for route/endpoint
                if any(x in dec_lower for x in ['route', 'get', 'post', 'put', 'delete', 'patch', 'webhook']):
                    self.add_capability("untrusted_input", node.lineno, f"Endpoint decorator @{dec_name}")
                    is_decorated = True
                # Check for tool
                if any(x in dec_lower for x in ['tool', 'mcp_tool', 'agent_tool', 'mcp.tool', 'm.tool']):
                    self.add_capability("command_exec", node.lineno, f"Tool decorator @{dec_name}")
                    is_decorated = True

        # Check function arguments for Untrusted Input
        for arg in node.args.args:
            is_untrusted_arg = False
            if is_decorated:
                is_untrusted_arg = True
            elif any(x in arg.arg.lower() for x in ['query', 'input', 'req', 'param', 'data', 'user']):
                is_untrusted_arg = True
            elif arg.annotation:
                ann_name = self._get_full_name(arg.annotation)
                if ann_name and 'request' in ann_name.lower():
                    is_untrusted_arg = True
            
            if is_untrusted_arg:
                self.add_capability("untrusted_input", node.lineno, f"Function argument: '{arg.arg}'")

        self.generic_visit(node)
        scope_data = self.pop_scope()
        self.evaluate_scope(scope_data, node.lineno)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_function(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_full_name(node.func)
        
        # If it's a short name from attribute, fallback to just attribute name
        short_name = ""
        if isinstance(node.func, ast.Attribute):
            short_name = node.func.attr
            
        # Category A: Private Data Access
        private_funcs = [
            'open', 'sqlite3.connect', 'connect', 'MongoClient', 'getenv',
            'environ.get', 'shutil.copy', 'listdir', 'read_text', 'read_bytes',
            'walk', 'create_engine', 'linecache.getline', 'fileinput.input',
            'socket.socket', 'socket.create_connection', 'aiohttp.ClientSession'
        ]
        private_shorts = [
            'open', 'connect', 'MongoClient', 'getenv', 'copy', 'listdir',
            'read_text', 'read_bytes', 'walk', 'create_engine', 'getline', 'input',
            'socket', 'create_connection', 'ClientSession'
        ]
        if func_name in private_funcs or short_name in private_shorts:
            self.add_capability("private_data", node.lineno, f"Call to private data API: {func_name or short_name}()")
            
        # Category B: Untrusted Input
        if func_name in ['input', 'get_json', 'form.get', 'query', 'search', 'retrieve'] or short_name in ['input', 'get_json', 'query', 'search', 'retrieve']:
            self.add_capability("untrusted_input", node.lineno, f"Call to input api: {func_name or short_name}()")

        # Category C: Command/Tool Execution
        exec_funcs = [
            'eval', 'exec', 'subprocess.run', 'subprocess.Popen', 'subprocess.call',
            'subprocess.check_output', 'subprocess.check_call', 'os.system', 'os.popen',
            'posix.system', 'importlib.import_module', 'ctypes.CDLL', 'ctypes.windll',
            'os.spawnl', 'os.spawnle', 'os.spawnlp', 'os.spawnlpe', 'os.spawnv', 'os.spawnve',
            'os.spawnvp', 'os.spawnvpe', 'os.posix_spawn', 'os.posix_spawnp', 'os.execv',
            'os.execve', 'os.execvp', 'os.execvpe', 'os.execl', 'os.execle', 'os.execlp',
            'os.execlpe', 'os.startfile', 'pty.spawn', 'fork'
        ]
        exec_shorts = [
            'eval', 'exec', 'run', 'Popen', 'call', 'check_output', 'check_call',
            'system', 'popen', 'import_module', 'CDLL', 'windll',
            'spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve',
            'spawnvp', 'spawnvpe', 'posix_spawn', 'posix_spawnp', 'execv',
            'execve', 'execvp', 'execvpe', 'execl', 'execle', 'execlp',
            'execlpe', 'startfile', 'spawn', 'fork'
        ]
        if func_name in exec_funcs or short_name in exec_shorts:
            # verify full module name prefix if short name matched
            is_valid_exec = True
            if short_name in ['run', 'Popen', 'call', 'check_output', 'check_call'] and not func_name.startswith('subprocess'):
                is_valid_exec = False
            if short_name in ['system', 'popen'] and not (func_name.startswith('os') or func_name.startswith('posix')):
                is_valid_exec = False
            if short_name in ['CDLL', 'windll'] and not func_name.startswith('ctypes'):
                is_valid_exec = False
            
            if is_valid_exec:
                self.add_capability("command_exec", node.lineno, f"Call to execution API: {func_name or short_name}()")

        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        resolved = self.aliases.get(node.id, node.id)
        if resolved in ['os.environ', 'environ']:
            self.add_capability("private_data", node.lineno, "Access to environ")
        elif resolved in ['sys.argv', 'argv']:
            self.add_capability("untrusted_input", node.lineno, "Access to argv")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # Category A: Private Data Access
        if isinstance(node.value, ast.Name):
            if node.value.id == 'os' and node.attr == 'environ':
                self.add_capability("private_data", node.lineno, "Access to os.environ")
            elif node.value.id == 'sys' and node.attr == 'argv':
                self.add_capability("untrusted_input", node.lineno, "Access to sys.argv")

        # Category B: Untrusted Input
        if isinstance(node.value, ast.Name) and node.value.id == 'request' and node.attr in ['args', 'json', 'form', 'headers']:
            self.add_capability("untrusted_input", node.lineno, f"Access to request.{node.attr}")

        self.generic_visit(node)

    def evaluate_scope(self, scope: Dict[str, Any], start_line: int):
        private_items = scope["private_data"]
        input_items = scope["untrusted_input"]
        exec_items = scope["command_exec"]

        has_private = len(private_items) > 0
        has_input = len(input_items) > 0
        has_exec = len(exec_items) > 0

        total_caps = sum([has_private, has_input, has_exec])
        
        # If this scope triggers capabilities, report and propagate up
        if total_caps == 3:
            # Lethal Trifecta!
            current_lines = {private_items[0][0], input_items[0][0], exec_items[0][0]}
            if not any(current_lines.issubset(existing) for existing in self.reported_combinations):
                self.reported_combinations.append(current_lines)
                details = [
                    f"Private Data ({private_items[0][1]} on line {private_items[0][0]})",
                    f"Untrusted Input ({input_items[0][1]} on line {input_items[0][0]})",
                    f"Tool Execution ({exec_items[0][1]} on line {exec_items[0][0]})"
                ]
                
                self.findings.append({
                    "file": self.file_path,
                    "line": start_line,
                    "name": "Lethal Trifecta Detected",
                    "severity": "CRITICAL",
                    "message": f"Dangerous convergence of capabilities inside {scope['name']}: {', '.join(details)}.",
                    "suggestion": "Separate data retrieval, user interaction, and system execution into decoupled modules. If tool execution is required, enforce strict human-in-the-loop validation."
                })
        elif total_caps == 2:
            # Elevated Agent Privilege
            selected_items = []
            if has_private:
                selected_items.append(private_items[0])
            if has_input:
                selected_items.append(input_items[0])
            if has_exec:
                selected_items.append(exec_items[0])
            current_lines = {item[0] for item in selected_items}
            if not any(current_lines.issubset(existing) for existing in self.reported_combinations):
                self.reported_combinations.append(current_lines)
                self.findings.append({
                    "file": self.file_path,
                    "line": start_line,
                    "name": "Elevated Agent Privilege",
                    "severity": "WARNING",
                    "message": f"Elevated attack surface in {scope['name']}. Two core agent capabilities are present in the same scope.",
                    "suggestion": "Ensure the agent's privilege is restricted and access boundaries are audited."
                })
        elif total_caps == 1:
            # Capability Registered (INFO)
            selected_item = (private_items or input_items or exec_items)[0]
            current_lines = {selected_item[0]}
            if not any(current_lines.issubset(existing) for existing in self.reported_combinations):
                self.reported_combinations.append(current_lines)
                self.findings.append({
                    "file": self.file_path,
                    "line": start_line,
                    "name": "Agent Capability Registered",
                    "severity": "INFO",
                    "message": f"Audit log: Core capability detected in {scope['name']}.",
                    "suggestion": "Monitor access controls for this component."
                })

        # Propagate capabilities to parent scope to track file-level combinations
        if self.scopes:
            parent = self.scopes[-1]
            parent["private_data"].extend(scope["private_data"])
            parent["untrusted_input"].extend(scope["untrusted_input"])
            parent["command_exec"].extend(scope["command_exec"])

    def visit_Module(self, node: ast.Module):
        self.generic_visit(node)
        # Evaluate global scope
        global_scope = self.pop_scope()
        self.evaluate_scope(global_scope, 1)


class JsTrifectaVisitor:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.scopes = []
        self.push_scope("global")
        self.reported_combinations = []

    def push_scope(self, name: str):
        self.scopes.append({
            "name": name,
            "private_data": [],
            "untrusted_input": [],
            "command_exec": []
        })

    def pop_scope(self) -> Dict[str, Any]:
        return self.scopes.pop()

    def add_capability(self, cap_type: str, line: int, detail: str):
        if self.scopes:
            self.scopes[-1][cap_type].append((line, detail))

    def evaluate_scope(self, scope: Dict[str, Any], start_line: int):
        private_items = scope["private_data"]
        input_items = scope["untrusted_input"]
        exec_items = scope["command_exec"]

        has_private = len(private_items) > 0
        has_input = len(input_items) > 0
        has_exec = len(exec_items) > 0

        total_caps = sum([has_private, has_input, has_exec])
        
        if total_caps == 3:
            current_lines = {private_items[0][0], input_items[0][0], exec_items[0][0]}
            if not any(current_lines.issubset(existing) for existing in self.reported_combinations):
                self.reported_combinations.append(current_lines)
                details = [
                    f"Private Data ({private_items[0][1]} on line {private_items[0][0]})",
                    f"Untrusted Input ({input_items[0][1]} on line {input_items[0][0]})",
                    f"Tool Execution ({exec_items[0][1]} on line {exec_items[0][0]})"
                ]
                self.findings.append({
                    "file": self.file_path,
                    "line": start_line,
                    "name": "Lethal Trifecta Detected",
                    "severity": "CRITICAL",
                    "message": f"Dangerous convergence of capabilities inside {scope['name']}: {', '.join(details)}.",
                    "suggestion": "Separate data retrieval, user interaction, and system execution into decoupled modules. If tool execution is required, enforce strict human-in-the-loop validation."
                })
        elif total_caps == 2:
            selected_items = []
            if has_private: selected_items.append(private_items[0])
            if has_input: selected_items.append(input_items[0])
            if has_exec: selected_items.append(exec_items[0])
            current_lines = {item[0] for item in selected_items}
            if not any(current_lines.issubset(existing) for existing in self.reported_combinations):
                self.reported_combinations.append(current_lines)
                self.findings.append({
                    "file": self.file_path,
                    "line": start_line,
                    "name": "Elevated Agent Privilege",
                    "severity": "WARNING",
                    "message": f"Elevated attack surface in {scope['name']}. Two core agent capabilities are present in the same scope.",
                    "suggestion": "Ensure the agent's privilege is restricted and access boundaries are audited."
                })
        elif total_caps == 1:
            selected_item = (private_items or input_items or exec_items)[0]
            current_lines = {selected_item[0]}
            if not any(current_lines.issubset(existing) for existing in self.reported_combinations):
                self.reported_combinations.append(current_lines)
                self.findings.append({
                    "file": self.file_path,
                    "line": start_line,
                    "name": "Agent Capability Registered",
                    "severity": "INFO",
                    "message": f"Audit log: Core capability detected in {scope['name']}.",
                    "suggestion": "Monitor access controls for this component."
                })

        # Propagate up
        if self.scopes:
            parent = self.scopes[-1]
            parent["private_data"].extend(scope["private_data"])
            parent["untrusted_input"].extend(scope["untrusted_input"])
            parent["command_exec"].extend(scope["command_exec"])

    def _get_line(self, node) -> int:
        loc = getattr(node, 'loc', None)
        if loc:
            start = getattr(loc, 'start', None)
            if start:
                line_val = getattr(start, 'line', None)
                if line_val is not None:
                    return line_val
        return 1

    def walk(self, node):
        if not node:
            return
        
        node_type = getattr(node, 'type', '')
        line = self._get_line(node)
        
        is_function = node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'MethodDefinition']
        is_class = node_type in ['ClassDeclaration', 'ClassExpression']
        
        if is_function:
            name = getattr(getattr(node, 'id', None), 'name', 'anonymous')
            if node_type == 'MethodDefinition':
                name = getattr(getattr(node, 'key', None), 'name', 'anonymous')
            self.push_scope(f"function:{name}")
            
            # Check function arguments for Untrusted Input
            params = getattr(node, 'params', [])
            for p in params:
                p_name = getattr(p, 'name', '')
                if p_name and any(x in p_name.lower() for x in ['query', 'input', 'req', 'param', 'data', 'user']):
                    self.add_capability("untrusted_input", line, f"Function argument: '{p_name}'")
                    
        elif is_class:
            name = getattr(getattr(node, 'id', None), 'name', 'anonymous')
            self.push_scope(f"class:{name}")

        # AST-specific nodes inspection
        if node_type == 'CallExpression':
            callee_str = self._resolve_callee(callee=node.callee)
            line_val = self._get_line(node)
            
            # Category A: Private Data Access
            if any(x in callee_str for x in ['readFile', 'readFileSync', 'connect', 'MongoClient']) or callee_str in ['open', 'require'] or (callee_str.startswith('fs.') and not callee_str.endswith('Sync')):
                self.add_capability("private_data", line_val, f"Call to private data API: {callee_str}()")
            
            # Category B: Untrusted Input
            if any(x in callee_str for x in ['readline', 'prompt', 'question']):
                self.add_capability("untrusted_input", line_val, f"Call to input api: {callee_str}()")
                
            # Category C: Command Execution
            if any(x in callee_str for x in ['exec', 'spawn', 'execSync', 'spawnSync', 'eval', 'Function']):
                self.add_capability("command_exec", line_val, f"Call to execution API: {callee_str}()")

        elif node_type == 'MemberExpression':
            member_str = self._resolve_callee(callee=node)
            line_val = self._get_line(node)
            if member_str == 'process.env':
                self.add_capability("private_data", line_val, "Access to process.env")
            elif member_str == 'process.argv':
                self.add_capability("untrusted_input", line_val, "Access to process.argv")
            elif member_str.startswith('req.') and any(x in member_str for x in ['query', 'body', 'params', 'headers']):
                self.add_capability("untrusted_input", line_val, f"Access to Express request: {member_str}")

        # Recurse children
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.walk(item)
            elif hasattr(value, 'type'):
                self.walk(value)

        # Pop scope
        if is_function or is_class:
            scope_data = self.pop_scope()
            self.evaluate_scope(scope_data, line)

    def _resolve_callee(self, callee) -> str:
        if not callee:
            return ""
        c_type = getattr(callee, 'type', '')
        if c_type == 'Identifier':
            return getattr(callee, 'name', '')
        elif c_type == 'MemberExpression':
            obj_str = self._resolve_callee(callee.object)
            prop_str = self._resolve_callee(callee.property)
            if obj_str and prop_str:
                return f"{obj_str}.{prop_str}"
            return prop_str or obj_str
        return ""
