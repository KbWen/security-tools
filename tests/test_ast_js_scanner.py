from ghostcheck.checks.ast_js_scanner import JsAstSecretChecker

def test_js_ast_concat():
    patterns = [{"name": "OpenAIKey", "pattern": "sk-[a-zA-Z0-9]{20,}", "severity": "HIGH"}]
    checker = JsAstSecretChecker(patterns)
    
    # 1. Test template literal
    code_tl = "const key = `sk-12345678901234567890`;"
    findings = checker.scan_file("test.js", code_tl)
    assert len(findings) == 1
    assert "JS AST" in findings[0]["pattern_name"]

    # 2. Test concatenation
    code_concat = "const key = 'sk-' + '12345678901234567890';"
    findings = checker.scan_file("test.js", code_concat)
    assert len(findings) == 1
    assert "JS AST" in findings[0]["pattern_name"]

    # 3. Test simple literal
    code_lit = "const key = 'sk-12345678901234567890';"
    findings = checker.scan_file("test.js", code_lit)
    assert len(findings) == 1

def test_js_ast_malformed():
    checker = JsAstSecretChecker([])
    # Should not crash on malformed JS
    findings = checker.scan_file("broken.js", "const x = ;")
    assert findings == []
