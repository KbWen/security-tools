import ast
import re

class AstSecretChecker:
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
        except (SyntaxError, ValueError, OverflowError):
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
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    value = node.value
                elif hasattr(ast, 'Str') and isinstance(node, ast.Str):
                    value = node.s
                
                if value is not None:
                    self._check_string(value, line_no, file_path, findings)

        return findings

    def _resolve_concat_with_members(self, node, depth=0):
        """Recursively resolves concatenation with depth limit."""
        if depth > self.MAX_RECURSION_DEPTH:
            raise RecursionError("Maximum AST concatenation depth exceeded")

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value, [node]
        if hasattr(ast, 'Str') and isinstance(node, ast.Str):
            return node.s, [node]
        
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_val, left_nodes = self._resolve_concat_with_members(node.left, depth + 1)
            right_val, right_nodes = self._resolve_concat_with_members(node.right, depth + 1)
            if left_val is not None and right_val is not None:
                return left_val + right_val, left_nodes + right_nodes + [node]
        
        return None, []

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
                        "value_preview": masked
                    })
            except Exception:
                continue
