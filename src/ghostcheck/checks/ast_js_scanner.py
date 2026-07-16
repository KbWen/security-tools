try:
    import esprima
except ImportError:
    esprima = None
import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class JsAstSecretChecker(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "jsastsecretchecker"

    @property
    def description(self) -> str:
        return "Scanner plugin for JsAstSecretChecker"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in ('.js', '.jsx', '.ts', '.tsx', '.html', '.vue', '.svelte', '.json'):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    """
    AST-based secret scanner for JavaScript/TypeScript using esprima.
    Detects secrets in template literals and string concatenations.
    """
    MAX_RECURSION_DEPTH = 50

    def __init__(self, patterns):
        self.patterns = patterns

    def scan_file(self, file_path, content):
        findings = []
        if esprima is None:
            return findings
        
        try:
            try:
                tree = esprima.parseModule(content, loc=True)
            except Exception:
                tree = esprima.parseScript(content, loc=True)
        except Exception:
            return findings

        self._walk_and_check(tree, file_path, findings)
        return findings

    def _walk_and_check(self, node, file_path, findings, depth=0):
        if not node or depth > self.MAX_RECURSION_DEPTH:
            return

        # Handle different node structures from esprima
        if hasattr(node, 'type'):
            # 1. Template Literals: `sk-` + ${part}
            if node.type == 'TemplateLiteral':
                full_text = ""
                checked_parts = set()
                for quasis in node.quasis:
                    part = quasis.value.cooked or ""
                    full_text += part
                    # Also check individual parts in case they are large enough secrets
                    if part and part not in checked_parts:
                        self._check_string(part, node.loc.start.line, file_path, findings, is_ast=True)
                        checked_parts.add(part)
                if full_text and full_text not in checked_parts:
                    self._check_string(full_text, node.loc.start.line, file_path, findings, is_ast=True)

            # 2. Binary Expressions (Concatenation): 'sk-' + 'part'
            elif node.type == 'BinaryExpression' and node.operator == '+':
                resolved = self._resolve_binop(node)
                if resolved:
                    self._check_string(resolved, node.loc.start.line, file_path, findings, is_ast=True)

            # 3. Simple Literals
            elif node.type == 'Literal' and isinstance(node.value, str):
                self._check_string(node.value, node.loc.start.line, file_path, findings)

            # Recursive walk for children
            if isinstance(node, (dict, list, esprima.nodes.Node)):
                items = []
                if isinstance(node, esprima.nodes.Node):
                    # For esprima nodes, we iterate over attributes
                    items = node.__dict__.items()
                elif isinstance(node, dict):
                    items = node.items()
                elif isinstance(node, list):
                    for item in node:
                        self._walk_and_check(item, file_path, findings, depth + 1)
                    return

                for key, value in items:
                    if isinstance(value, list):
                        for item in value:
                            self._walk_and_check(item, file_path, findings, depth + 1)
                    elif isinstance(value, (dict, esprima.nodes.Node)):
                        self._walk_and_check(value, file_path, findings, depth + 1)

    def _resolve_binop(self, node, depth=0):
        if depth > self.MAX_RECURSION_DEPTH:
            return ""
        
        left_val = self._get_literal_val(node.left, depth + 1)
        right_val = self._get_literal_val(node.right, depth + 1)
        
        return (left_val or "") + (right_val or "")

    def _get_literal_val(self, node, depth):
        if not hasattr(node, 'type'):
            return ""
        if node.type == 'Literal':
            return str(node.value) if node.value is not None else ""
        if node.type == 'BinaryExpression' and node.operator == '+':
            return self._resolve_binop(node, depth)
        return ""

    def _check_string(self, value, line_no, file_path, findings, is_ast=False):
        for p in self.patterns:
            try:
                match = re.search(p['pattern'], value)
                if match:
                    val = match.group(0)
                    masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
                    
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "pattern_name": f"{p['name']}{' (JS AST)' if is_ast else ''}",
                        "severity": p['severity'],
                        "value_preview": masked,
                        "suggestion": p.get('remediation', "Rotate or revoke this secret.")
                    })
            except Exception:
                continue
