import ast
import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class AstSecretChecker(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "astsecretchecker"

    @property
    def description(self) -> str:
        return "Scanner plugin for AstSecretChecker"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        import os
        findings = []
        for file_path in files:
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in ('.py', '.pyw', '.pyi'):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    """
    Advanced secret scanner that uses AST to detect obfuscated secrets.
    Focuses on detecting secrets formed via string concatenation.
    """
    MAX_RECURSION_DEPTH = 100

    def __init__(self, patterns):
        self.patterns = patterns

    def scan_file(self, file_path, content):
        findings = []
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, OverflowError, RecursionError):
            # Gracefully handle broken files or extremely complex ones
            return findings

        processed_nodes = set()

        for node in ast.walk(tree):
            line_no = getattr(node, 'lineno', 1)
            
            # Avoid duplicate reporting for nested BinOps
            if node in processed_nodes:
                continue

            # 1. Check for string concatenations
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                try:
                    full_val, members = self._resolve_concat_with_members(node)
                    if full_val:
                        # Mark all member nodes as processed
                        for m in members:
                            processed_nodes.add(m)
                        self._check_string(full_val, line_no, file_path, findings, is_concat=True)
                except RecursionError:
                    # Log or skip if too deep
                    continue

            # 2. Simple constants
            elif isinstance(node, (ast.Constant, getattr(ast, 'Str', type(None)))):
                value = None
                if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                    value = node.value.decode('utf-8', errors='ignore') if isinstance(node.value, bytes) else node.value
                elif hasattr(ast, 'Str') and isinstance(node, getattr(ast, 'Str', type(None))):
                    value = node.s
                
                if value is not None:
                    self._check_string(value, line_no, file_path, findings)

            # 3. f-strings
            elif isinstance(node, ast.JoinedStr):
                full_val = ""
                for v in node.values:
                    if isinstance(v, ast.Constant) and isinstance(v.value, (str, bytes)):
                        full_val += v.value.decode('utf-8', errors='ignore') if isinstance(v.value, bytes) else v.value
                if full_val:
                    self._check_string(full_val, line_no, file_path, findings, is_concat=True)

            # 4. .join() calls
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'join':
                if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                    if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                        joined = ""
                        for elt in node.args[0].elts:
                            val, _ = self._resolve_concat_with_members(elt)
                            if val: joined += val
                        if joined:
                            self._check_string(joined, line_no, file_path, findings, is_concat=True)

        return findings

    def _resolve_concat_with_members(self, node, depth=0):
        """Recursively resolves concatenation with depth limit."""
        if depth > self.MAX_RECURSION_DEPTH:
            return "", []

        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            val = node.value.decode('utf-8', errors='ignore') if isinstance(node.value, bytes) else node.value
            return val, [node]
        if hasattr(ast, 'Str') and isinstance(node, getattr(ast, 'Str', type(None))):
            return node.s, [node]
        
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_val, left_nodes = self._resolve_concat_with_members(node.left, depth + 1)
            right_val, right_nodes = self._resolve_concat_with_members(node.right, depth + 1)
            return (left_val or "") + (right_val or ""), left_nodes + right_nodes + [node]
        
        return "", []

    def _check_string(self, value, line_no, file_path, findings, is_concat=False):
        for p in self.patterns:
            try:
                match = re.search(p['pattern'], value)
                if match:
                    # Mask the value for reporting
                    val = match.group(0)
                    masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
                    
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "pattern_name": f"{p['name']}{' (AST Concat)' if is_concat else ''}",
                        "severity": p['severity'],
                        "value_preview": masked,
                        "suggestion": p.get('remediation', "Rotate or revoke this secret.")
                    })
            except Exception:
                continue
