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

def test_ast_fstring_and_join():
    patterns = [{"name": "AWS Key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "HIGH"}]
    checker = AstSecretChecker(patterns)
    
    # 1. f-strings
    fstring_content = 'f"prefix {some_var} AKIA1234567890ABCDEF suffix"'
    findings_f = checker.scan_file("test.py", fstring_content)
    assert len(findings_f) == 2
    
    # 2. .join()
    join_content = '"".join(["AKIA", "1234567890ABCDEF"])'
    findings_j = checker.scan_file("test.py", join_content)
    assert len(findings_j) == 1

def test_ast_bytes_and_errors(tmp_path):
    patterns = [{"name": "AWS Key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "HIGH"}]
    checker = AstSecretChecker(patterns)
    
    # 1. Bytes literal (e.g. b"AKIA...")
    content_bytes = 'key = b"AKIA1234567890ABCDEF"'
    findings_b = checker.scan_file("test.py", content_bytes)
    assert len(findings_b) == 1
    
    # 2. File read exception handling in scan method
    bad_file = tmp_path / "non_existent.py"
    res = checker.scan([str(bad_file)], None)
    assert res == []
    
    # 3. Recursion limit resolution depth exceeded
    checker.MAX_RECURSION_DEPTH = 1
    content_deep = '"a" + "b" + "c"'
    # Should hit depth limit and return safely
    findings_deep = checker.scan_file("test.py", content_deep)
    assert findings_deep == []

