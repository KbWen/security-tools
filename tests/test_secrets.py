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
    assert findings[0]['value_preview'] == "key-*bcde"

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

def test_secrets_bypass_and_placeholders(tmp_path):
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text(json.dumps([
        {"name": "AWS Access Key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "CRITICAL"},
        {"name": "Generic Secret Key", "pattern": "(?i)(secret|key|password|passwd|pwd|token)\\s*[:=]\\s*['\"]?[a-zA-Z0-9_-]{8,}['\"]?", "severity": "HIGH"}
    ]))
    scanner = SecretScanner(str(patterns_file))

    # 1. Active AWS key with comment containing 'todo'
    res1 = scanner.scan_file("test.py", 'AWS_ACCESS_KEY_ID = "AKIA1234567890123456" # TODO: remove this')
    assert len(res1) > 0

    # 2. Active AWS key containing 'XXX'
    res2 = scanner.scan_file("test.py", 'TOKEN = "AKIA1234567890123XXX"')
    assert len(res2) > 0

    # 3. Real generic secret key (with spaces around '=')
    res3 = scanner.scan_file("test.py", 'my_password = "SuperSecretSecurePassword123"')
    assert len(res3) > 0

    # 4. Generic key with placeholder value (should be ignored)
    res4 = scanner.scan_file("test.py", 'my_password = "your-password-here"')
    assert len(res4) == 0

    # 5. Generic key with all xxxxxxxx (should be ignored)
    res5 = scanner.scan_file("test.py", 'my_password = "xxxxxxxxxxxx"')
    assert len(res5) == 0

