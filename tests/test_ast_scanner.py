import pytest
from ghostcheck.checks.ast_scanner import AstSecretChecker

def test_ast_concat():
    patterns = [{"name": "AWS Key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "HIGH"}]
    checker = AstSecretChecker(patterns)
    
    content = 'key = "AKIA" + "1234567890ABCDEF"'
    findings = checker.scan_file("test.py", content)
    
    assert len(findings) == 1
    assert "AKIA" in findings[0]['value_preview']
    assert "AST Concat" in findings[0]['pattern_name']

def test_ast_nested_concat():
    patterns = [{"name": "AWS Key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "HIGH"}]
    checker = AstSecretChecker(patterns)
    
    content = 'key = "AK" + ("IA" + "1234567890ABCDEF")'
    findings = checker.scan_file("test.py", content)
    
    # Simple walk might report multiple times if not careful? 
    # Actually our implementation uses processed_nodes to avoid duplicates
    assert len(findings) == 1

def test_ast_recursion_limit():
    patterns = [{"name": "Long", "pattern": ".*", "severity": "LOW"}]
    checker = AstSecretChecker(patterns)
    checker.MAX_RECURSION_DEPTH = 5
    
    # 6 additions
    content = '"a" + "b" + "c" + "d" + "e" + "f" + "g"'
    # This should trigger RecursionError internally and return what it can or handle gracefully
    findings = checker.scan_file("test.py", content)
    assert isinstance(findings, list)

def test_ast_syntax_error():
    checker = AstSecretChecker([])
    findings = checker.scan_file("broken.py", "if True print('hi')")
    assert findings == []
