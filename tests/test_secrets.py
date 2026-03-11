import os
import json
from ghostcheck.checks.secrets import SecretScanner

def test_secret_scan(tmp_path):
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text(json.dumps([
        {"name": "Fake Key", "pattern": "key-[a-z]{5}", "severity": "HIGH"}
    ]))
    
    scanner = SecretScanner(str(patterns_file))
    content = "This is a key-abcde and another key-12345"
    findings = scanner.scan_file("test.txt", content)
    
    assert len(findings) == 1
    assert findings[0]['pattern_name'] == "Fake Key"
    assert findings[0]['value_preview'] == "****"

def test_severity_adjustment():
    scanner = SecretScanner.__new__(SecretScanner)
    
    # AI log -> Upgrade
    assert scanner._get_severity_modifier("conversation_log.txt") == 1
    assert scanner._get_severity_modifier("chat_session.md") == 1
    
    # Example/Test -> Downgrade
    assert scanner._get_severity_modifier("config.example") == -1
    assert scanner._get_severity_modifier("tests/test_file.py") == -1
    
    # Normal -> 0
    assert scanner._get_severity_modifier("src/main.py") == 0

def test_adjust_severity():
    scanner = SecretScanner.__new__(SecretScanner)
    assert scanner._adjust_severity("HIGH", 1) == "CRITICAL"
    assert scanner._adjust_severity("HIGH", -1) == "MEDIUM"
    assert scanner._adjust_severity("CRITICAL", 1) == "CRITICAL"
    assert scanner._adjust_severity("INFO", -1) == "INFO"
