import pytest
import os
import json
import tempfile
from ghostcheck.ignorefile import IgnoreMatcher
from ghostcheck.checks.secrets import SecretScanner, _is_placeholder_value, _is_likely_generic_false_positive

def test_ignore_matcher_default_ignores():
    matcher = IgnoreMatcher()
    
    # Verify new default ignore entries are active
    assert matcher.is_ignored('dist/bundle.js') is True
    assert matcher.is_ignored('.next/static/chunks/main.js') is True
    assert matcher.is_ignored('.venv/lib/python3.10/site-packages/pkg.py') is True
    assert matcher.is_ignored('node_modules/express/index.js') is True
    assert matcher.is_ignored('.pytest_cache/v/cache/lastfailed') is True
    
    # Verify regular source files are NOT ignored
    assert matcher.is_ignored('src/app/index.ts') is False
    assert matcher.is_ignored('components/Header.tsx') is False

def test_secret_scanner_expanded_extensions():
    # Test allowed extensions list in SecretScanner
    with tempfile.NamedTemporaryFile(suffix='.secret_patterns.json', mode='w+', delete=False) as f:
        json.dump([
            {
                "name": "Dummy Secret Key",
                "pattern": r"sk_" + r"live_[a-zA-Z0-9]{24}",
                "severity": "CRITICAL",
                "remediation": "Revoke secret"
            }
        ], f)
        patterns_path = f.name
        
    try:
        scanner = SecretScanner(patterns_path)
        
        # Test scanning TSX, JSX, TOML, and TF files
        sample_files = ['App.tsx', 'Header.jsx', 'credentials.toml', 'main.tf']
        secret_content = 'const KEY = "' + 'sk_' + 'live_123456789012345678901234";'
        
        for name in sample_files:
            with tempfile.NamedTemporaryFile(suffix=name, mode='w+', delete=False) as tf:
                tf.write(secret_content)
                tf_path = tf.name
                
            try:
                findings = scanner.scan([tf_path], config={})
                assert len(findings) > 0, f"Expected SecretScanner to detect secret in {name}"
                assert findings[0]['pattern_name'] == "Dummy Secret Key"
            finally:
                if os.path.exists(tf_path):
                    os.remove(tf_path)
    finally:
        if os.path.exists(patterns_path):
            os.remove(patterns_path)

def test_placeholder_precision():
    # Exact placeholders should return True
    assert _is_placeholder_value("your-api-key") is True
    assert _is_placeholder_value("your_secret") is True
    assert _is_placeholder_value("<your-api-key>") is True
    
    # Real credentials containing 'your_secret' as part of token should NOT be discarded
    assert _is_placeholder_value("sk_live_998877_your_secret_key_abcdef") is False

def test_generic_false_positive_extension_ends():
    # File paths ending in extensions should be generic FPs
    assert _is_likely_generic_false_positive("config/settings.json") is True
    
    # Strings with extension in middle shouldn't trigger filename suffix match
    assert _is_likely_generic_false_positive("key_v1.json_token_998877_long_string_abc") is False

def test_ignore_matcher_path_variations():
    matcher = IgnoreMatcher()
    
    # Test leading slash, Windows backslash, and relative path variations
    assert matcher.is_ignored('/dist/app.js') is True
    assert matcher.is_ignored('.\\dist\\app.js') is True
    assert matcher.is_ignored('dist\\sub\\chunk.js') is True
    assert matcher.is_ignored('./.next/server/page.js') is True

def test_secret_scanner_your_prefix_token_not_bypassed():
    # Verify real tokens starting with 'your_' are NOT falsely suppressed
    assert _is_placeholder_value("your_live_token_998877665544332211") is False
    assert _is_placeholder_value("your-production-key-99887766554433") is False


def test_shadow_ai_fstring_ast_folding():
    """Verify ShadowAIDetector properly folds f-strings with ast.FormattedValue (e.g. __import__(f"{'open'}{'ai'}"))"""
    from ghostcheck.checks.shadow_ai import ShadowAIDetector
    detector = ShadowAIDetector(config={"shadow_ai": {"blocked_sdks": ["openai"]}})
    code = "__import__(f\"{'open'}{'ai'}\")\n"
    findings = detector.scan_file("dynamic_import.py", code)
    assert any(f.get("rule_id") == "GSA-01" or "openai" in f.get("message", "").lower() for f in findings), \
        f"Expected ShadowAIDetector to detect f-string obfuscated import, got: {findings}"


def test_ast_scanner_fstring_secret_folding():
    """Verify AstSecretChecker folds f-strings with ast.FormattedValue for secrets"""
    from ghostcheck.checks.ast_scanner import AstSecretChecker
    patterns = [{
        "name": "Test Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{16,}",
        "severity": "CRITICAL"
    }]
    checker = AstSecretChecker(patterns)
    code = "api_key = f\"sk_live_{'12345678901234567890'}\"\n"
    findings = checker.scan_file("secrets.py", code)
    assert len(findings) == 1, f"Expected 1 finding for f-string secret, got: {findings}"


def test_ignore_matcher_negation_overrides_default():
    """Verify that !pattern in IgnoreMatcher properly overrides previous patterns (Last-Matching-Pattern)"""
    matcher = IgnoreMatcher(patterns=['dist/', '!dist/bundle.js'])
    # dist/bundle.js should be un-ignored by the negation rule
    assert matcher.is_ignored('dist/bundle.js') is False
    # dist/other.js should remain ignored
    assert matcher.is_ignored('dist/other.js') is True


def test_data_exfiltration_integrated_in_scanner(tmp_path):
    """Verify that DataExfiltrationDetector is enabled and executed during Scanner.scan()"""
    from ghostcheck.scanner import Scanner

    exfil_code = """
import os
import openai

env = os.environ
secret = env.get("API_KEY")
openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": secret}]
)
"""
    src_file = tmp_path / "exfil.py"
    src_file.write_text(exfil_code, encoding="utf-8")

    scanner = Scanner(root_path=str(tmp_path), ignore_enabled=False)
    findings = scanner.scan()
    assert any("data exfiltration" in str(f.get("name", "")).lower() or
               "prompt leakage" in str(f.get("name", "")).lower() for f in findings), \
        f"Expected DataExfiltrationDetector findings in Scanner.scan(), got: {findings}"
