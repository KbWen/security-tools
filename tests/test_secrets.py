import os
import json
from pathlib import Path
from ghostcheck.checks.secrets import SecretScanner, _mask_token

REAL_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "src" / "ghostcheck" / "data" / "secret_patterns.json"

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

    # 6. Generic key with common word (should be ignored)
    res6 = scanner.scan_file("test.py", 'key = "Authorization"')
    assert len(res6) == 0

    # 7. Generic key with path / file name (should be ignored)
    res7 = scanner.scan_file("test.py", 'secret_path = "config/secrets.json"')
    assert len(res7) == 0

    # 8. Generic key with low entropy word (should be ignored)
    res8 = scanner.scan_file("test.py", 'symmetric_key = "symmetric"')
    assert len(res8) == 0

    # 9. Generic key with algorithm name (should be ignored)
    res9 = scanner.scan_file("test.py", 'algorithm = "HS256"')
    assert len(res9) == 0


def test_multi_secret_single_line_and_full_context_masking():
    scanner = SecretScanner(str(REAL_PATTERNS_PATH))

    openai_key = "sk-proj-" + "AbCdEf1234567890_xyz-9876543210"
    anthropic_key = "sk-ant-api03-" + "QwErTy1234567890_abc-1122334455"
    line_mixed = f'OPENAI="{openai_key}" ANTHROPIC="{anthropic_key}"'

    findings_mixed = scanner.scan_file("config.py", line_mixed)
    assert len(findings_mixed) == 2
    by_name = {f["pattern_name"]: f for f in findings_mixed}
    assert set(by_name.keys()) == {"OpenAI API Key", "Anthropic API Key"}
    assert by_name["OpenAI API Key"]["_raw_value"] == openai_key
    assert by_name["Anthropic API Key"]["_raw_value"] == anthropic_key
    for finding in findings_mixed:
        assert openai_key not in finding["context"]
        assert anthropic_key not in finding["context"]

    openai_key_1 = "sk-proj-" + "FirstKey1234567890_aaa-11111111"
    openai_key_2 = "sk-proj-" + "SecondKey0987654321_bbb-22222222"
    line_same_pattern = f'PRIMARY="{openai_key_1}" SECONDARY="{openai_key_2}"'

    findings_same = scanner.scan_file("config.py", line_same_pattern)
    assert len(findings_same) == 2
    assert all(f["pattern_name"] == "OpenAI API Key" for f in findings_same)
    assert {f["_raw_value"] for f in findings_same} == {openai_key_1, openai_key_2}
    for finding in findings_same:
        assert openai_key_1 not in finding["context"]
        assert openai_key_2 not in finding["context"]


def test_placeholder_followed_by_real_secret_on_same_line():
    scanner = SecretScanner(str(REAL_PATTERNS_PATH))
    real_token = "RealSecret" + "Token987654321"
    line = f'key="your-key-here" token="{real_token}"'

    findings = scanner.scan_file("app.py", line)
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "Generic Secret Key"
    assert findings[0]["_raw_value"] == real_token
    assert real_token not in findings[0]["context"]


def test_modern_anthropic_and_openai_formats_without_duplication():
    scanner = SecretScanner(str(REAL_PATTERNS_PATH))

    anthropic_key = "sk-ant-api03-" + "AbCdEf1234567890_xyz-9876543210"
    res_anthropic = scanner.scan_file("env.py", f'ANTHROPIC_API_KEY = "{anthropic_key}"')
    assert len(res_anthropic) == 1
    assert res_anthropic[0]["pattern_name"] == "Anthropic API Key"
    assert res_anthropic[0]["_raw_value"] == anthropic_key

    openai_key = "sk-proj-" + "ZyXwVu1234567890_mno-5566778899"
    res_openai = scanner.scan_file("env.py", f'OPENAI_API_KEY = "{openai_key}"')
    assert len(res_openai) == 1
    assert res_openai[0]["pattern_name"] == "OpenAI API Key"
    assert res_openai[0]["_raw_value"] == openai_key

    legacy_antigravity = "sk-antigravity-" + "1234567890abcdef123456"
    res_compat = scanner.scan_file("env.py", f'API = "{legacy_antigravity}"')
    assert len(res_compat) == 1
    assert res_compat[0]["pattern_name"] == "OpenAI API Key"
    assert res_compat[0]["_raw_value"] == legacy_antigravity


def test_word_boundary_false_positive_guard():
    scanner = SecretScanner(str(REAL_PATTERNS_PATH))
    content = "\n".join([
        'identifier = "task-' + '1234567890abcdefghijkl"',
        'css = "my-sk-' + '1234567890abcdefghijkl"',
        'label = "my-sk-ant-' + '1234567890abcdefghijkl"',
    ])

    findings = scanner.scan_file("ui.ts", content)
    provider_findings = [
        f for f in findings
        if f["pattern_name"] in {"OpenAI API Key", "Anthropic API Key"}
    ]
    assert provider_findings == []


def test_specific_over_generic_dedup_preserves_independent_generic_secret():
    scanner = SecretScanner(str(REAL_PATTERNS_PATH))
    anthropic_key = "sk-ant-api03-" + "MnOpQr1234567890_uvw-1234567890"
    password_val = "SuperSecret" + "Password9876!"
    line = f'api_key="{anthropic_key}" password="{password_val}"'

    findings = scanner.scan_file("settings.py", line)
    assert len(findings) == 2
    by_name = {f["pattern_name"]: f for f in findings}
    assert set(by_name.keys()) == {"Anthropic API Key", "Generic Secret Key"}
    assert by_name["Anthropic API Key"]["_raw_value"] == anthropic_key
    assert by_name["Generic Secret Key"]["_raw_value"] == password_val
    for finding in findings:
        assert anthropic_key not in finding["context"]
        assert password_val not in finding["context"]


def test_positional_json_key_check(tmp_path):
    patterns_file = tmp_path / "custom_patterns.json"
    patterns_file.write_text(json.dumps([
        {"name": "Custom Foo Token", "pattern": "foo_tok_[0-9]+", "severity": "HIGH"}
    ]))
    scanner = SecretScanner(str(patterns_file))

    line = '{"foo_tok_123": "foo_tok_123"}'
    findings = scanner.scan_file("data.json", line)
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "Custom Foo Token"
    assert findings[0]["_raw_value"] == "foo_tok_123"


def test_equals_in_colon_delimited_and_db_uri_secrets():
    scanner = SecretScanner(str(REAL_PATTERNS_PATH))

    aws_secret_1 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+AB" + "="
    aws_secret_2 = "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210+Z" + "=="
    assert len(aws_secret_1) == 40
    assert len(aws_secret_2) == 40

    res_single = scanner.scan_file("config.yaml", f'aws_secret_access_key: "{aws_secret_1}"')
    assert len(res_single) == 1
    assert res_single[0]["pattern_name"] == "AWS Secret Key"
    assert res_single[0]["_raw_value"] == aws_secret_1
    assert aws_secret_1 not in res_single[0]["context"]

    res_two = scanner.scan_file(
        "config.yaml",
        f'aws_secret_access_key: "{aws_secret_1}" aws_secret_access_key: "{aws_secret_2}"',
    )
    assert len(res_two) == 2
    assert {f["_raw_value"] for f in res_two} == {aws_secret_1, aws_secret_2}
    for finding in res_two:
        assert aws_secret_1 not in finding["context"]
        assert aws_secret_2 not in finding["context"]

    pass_left = "MyRealSecretPass12345"
    pass_right = "xyz987654321"
    colon_password = pass_left + "=" + pass_right
    res_colon = scanner.scan_file("config.yaml", f'password: "{colon_password}"')
    assert len(res_colon) == 1
    assert res_colon[0]["_raw_value"] == colon_password
    assert pass_left not in res_colon[0]["context"]
    assert pass_right not in res_colon[0]["context"]

    db_pass = "MySuperSecretPass" + "="
    db_line = f'DATABASE_URL = "postgres://admin:{db_pass}@db.prod.internal:5432/app"'
    res_db = scanner.scan_file("config.py", db_line)
    assert len(res_db) == 1
    assert res_db[0]["pattern_name"] == "Database Connection String"
    assert db_pass not in res_db[0]["context"]


def test_mask_token_length_boundaries():
    assert _mask_token("12345678") == "****"
    assert _mask_token("123456789") == "1234*6789"


def test_same_line_substring_sibling_secrets(tmp_path):
    patterns_file = tmp_path / "substring_patterns.json"
    patterns_file.write_text(json.dumps([
        {"name": "Pattern A", "pattern": "PrefixSubSecret[0-9]+Suffix", "severity": "HIGH"},
        {"name": "Pattern B", "pattern": "SubSecret[0-9]+", "severity": "HIGH"},
    ]))
    scanner = SecretScanner(str(patterns_file))

    secret_b = "SubSecret" + "12345"
    secret_a = "Prefix" + secret_b + "Suffix"
    line = f'A="{secret_a}" B="{secret_b}"'

    findings = scanner.scan_file("sub.txt", line)
    assert len(findings) == 2
    assert {f["pattern_name"] for f in findings} == {"Pattern A", "Pattern B"}
    for finding in findings:
        assert secret_a not in finding["context"]
        assert secret_b not in finding["context"]


def test_duplicate_identical_secret_twice_on_one_line():
    scanner = SecretScanner(str(REAL_PATTERNS_PATH))
    openai_key = "sk-proj-" + "DuplicateKey1234567890_xyz-11223344"
    line = f'KEY_A="{openai_key}" KEY_B="{openai_key}"'

    findings = scanner.scan_file("dup.py", line)
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "OpenAI API Key"
    assert findings[0]["_raw_value"] == openai_key
    assert openai_key not in findings[0]["context"]
