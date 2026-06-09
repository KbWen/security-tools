from ghostcheck.checks.severity_engine import SeverityEngine

def test_severity_downgrade():
    engine = SeverityEngine("/root")
    finding = {"file": "tests/data.py", "severity": "HIGH", "value_preview": "sk-1234567890"}
    
    # Path based downgrade
    engine.adjust_finding(finding)
    assert finding["severity"] == "MEDIUM"
    assert "test" in finding["adjustment_reason"]

def test_severity_entropy():
    engine = SeverityEngine("/root")
    # Low entropy string
    finding = {"file": "src/main.py", "severity": "HIGH", "value_preview": "aaaaaaaaaaaa"}
    engine.adjust_finding(finding)
    assert finding["severity"] == "MEDIUM"
    assert "low entropy" in finding["adjustment_reason"]

def test_severity_no_extension():
    engine = SeverityEngine("/root")
    finding = {"file": "bin/server", "severity": "HIGH", "value_preview": "G6fW9zR4vL2k7Qp8N3mJ5hX1bY0aD9cE7vS4wZi8uT1o"}
    # Should adjust severity but not fail/crash on missing extension
    engine.adjust_finding(finding)
    # The file has no extension. It is not in test or AI output directories.
    # Severity should remain HIGH (not downgraded)
    assert finding["severity"] == "HIGH"

def test_severity_invalid_paths():
    engine = SeverityEngine("/root")
    # None path
    finding_none = {"file": None, "severity": "HIGH"}
    engine.adjust_finding(finding_none)
    assert finding_none["severity"] == "HIGH"
    
    # Missing file field
    finding_missing = {"severity": "HIGH"}
    engine.adjust_finding(finding_missing)
    assert finding_missing["severity"] == "HIGH"

    # Non-string path
    finding_dict = {"file": {"path": "tests/data.py"}, "severity": "HIGH"}
    engine.adjust_finding(finding_dict)
    assert finding_dict["severity"] == "HIGH"

def test_scoring_custom_severities():
    from ghostcheck.scoring import ScoringEngine
    se = ScoringEngine()
    
    # Custom/invalid severities mapped to standard levels
    findings = [
        {"severity": "warning"},      # -> MEDIUM (5 penalty)
        {"severity": "ERR"},          # -> HIGH (15 penalty)
        {"severity": "FATAL"},        # -> HIGH (15 penalty)
        {"severity": "UNRECOGNIZED"}, # -> LOW (1 penalty)
        {"severity": None}            # -> INFO (0 penalty)
    ]
    grade, score = se.calculate_score(findings)
    # Total penalty = 5 + 15 + 15 + 1 = 36. Score should be 100 - 36 = 64.
    assert score == 64

def test_scanner_sanitization():
    from ghostcheck.scanner import Scanner
    scanner = Scanner(root_path=".")
    
    # Passing findings with invalid file/severity types should not crash the scanner pipeline
    raw_findings = [
        {"file": None, "severity": None, "line": 1, "name": "test_issue"},
        {"file": {"path": "test.py"}, "severity": 123, "line": 1, "name": "test_issue"}
    ]
    
    # Actually run it through scanner's filter logic to ensure coverage of src/ghostcheck/scanner.py
    scanner.results_cache = {"dummy_fp": raw_findings}
    scanner._get_file_fingerprint = lambda path: "dummy_fp"
    scanner._iter_files = lambda limit_files: [(".", ["dummy_file.py"])]
    
    # Run scan
    results = scanner.scan()
    assert len(results) >= 2
    assert results[0]['file'] == ""
    assert results[0]['severity'] == "INFO"
    assert results[1]['file'] == ""
    assert results[1]['severity'] == "INFO"

def test_kebab_case_hardening():
    from ghostcheck.checks.entropy_scanner import _is_kebab_case_false_positive
    
    # Standard CSS class (should be recognized as false positive -> return True)
    assert _is_kebab_case_false_positive("bg-indigo-500") is True
    assert _is_kebab_case_false_positive("grid-3") is True
    
    # Mixed-case base64 secret with dashes (should NOT be marked false positive -> return False)
    assert _is_kebab_case_false_positive("Abcdefgh-Ijkl-Mnop-Qrst-Uvwx") is False
    
    # Too long kebab string (should NOT be marked false positive -> return False)
    assert _is_kebab_case_false_positive("this-is-a-very-long-obfuscated-kebab-string-that-exceeds-forty-characters") is False
    
    # Too many parts (should NOT be marked false positive -> return False)
    assert _is_kebab_case_false_positive("one-two-three-four-five-six") is False
    
    # Pure alpha UUID (should NOT be marked false positive -> return False if uppercase present, or if too many parts)
    # Standard UUID has 5 parts: 8-4-4-4-12. If all lowercase alpha, it has 5 parts:
    # abcdefab-cdef-abcd-abcd-abcdefabcdef -> wait, abcdefabcdef is length 12, which is <= 12.
    # But let's check: len("abcdefab-cdef-abcd-abcd-abcdefabcdef") is 36, which is <= 40.
    # Parts: abcdefab (8), cdef (4), abcd (4), abcd (4), abcdefabcdef (12).
    # Since it is all lowercase, it would match if <= 5 parts. Standard UUID has exactly 5 parts.
    # But if it has more parts, or if it is mixed case, it won't match.
    # Let's verify:
    assert _is_kebab_case_false_positive("abcdefab-Cdef-abcd-abcd-abcdefabcdef") is False # Mixed case
    assert _is_kebab_case_false_positive("abcdefab-cdef-abcd-abcd-abcdefabcdefg") is False # Part length 13 (> 12)

def test_severity_ai_output_upgrade():
    engine = SeverityEngine("/root")
    # Path with AI generated output directory (.antigravity)
    finding = {"file": ".antigravity/chat_history.json", "severity": "MEDIUM"}
    engine.adjust_finding(finding)
    assert finding["severity"] == "HIGH"
    assert "AI generated" in finding["adjustment_reason"]


