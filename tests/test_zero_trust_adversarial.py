import os
import sys
import tempfile
import pytest
from ghostcheck.scanner import Scanner
from ghostcheck.checks.shadow_ai import ShadowAIDetector
from ghostcheck.checks.ast_scanner import AstSecretChecker
from ghostcheck.checks.tamper_auditor import TamperAuditor
from ghostcheck.ignorefile import IgnoreMatcher

# Vector 1: Hostile & Malformed Inputs (語法破壞與畸形輸入)
def test_zero_trust_malformed_syntax_graceful_degradation():
    """Verify that completely broken/malformed Python code does not crash the AST scanner."""
    detector = ShadowAIDetector()
    broken_py = "def func(:\n    import openai broken syntax )))\n"
    # Should fall back to regex without crashing
    findings = detector.scan_file("broken.py", broken_py)
    assert any(f.get("name") == "unauthorized_ai_sdk_python" for f in findings)

def test_zero_trust_deeply_nested_binop_recursion():
    """Verify that extreme BinOp nesting (e.g. 50+ additions) handles recursion safely."""
    detector = ShadowAIDetector()
    # Generate 'o' + 'p' + 'e' + 'n' + 'a' + 'i' repeated
    nested_str = " + ".join([f"'{c}'" for c in "openai"])
    code = f"__import__({nested_str})\n"
    findings = detector.scan_file("nested_heavy.py", code)
    assert any(f.get("name") == "unauthorized_ai_sdk_python" for f in findings)

def test_zero_trust_binary_and_null_bytes(tmp_path):
    """Verify that files with null bytes or binary garbage are safely rejected by _read_file_safe."""
    scanner = Scanner(root_path=str(tmp_path))
    bin_file = tmp_path / "corrupted.bin"
    bin_file.write_bytes(b"\x00\xff\xfe\x01\x02\x03\x00\x00secret_data")
    
    # Reading binary file should return None safely
    res = scanner._read_file_safe(str(bin_file))
    assert res is None

# Vector 2: Path Traversal & Symlink Attacks (路徑逃逸防禦)
def test_zero_trust_path_traversal_boundaries(tmp_path):
    """Verify that path traversal attempts outside root_path are blocked."""
    scanner = Scanner(root_path=str(tmp_path))
    
    # Outside file path
    outside_file = "/etc/passwd" if sys.platform != "win32" else "C:\\Windows\\System32\\drivers\\etc\\hosts"
    assert scanner._is_safe_path(outside_file) is False
    assert scanner._is_safe_path("../../../outside.txt") is False
    assert scanner._is_safe_path(None) is False
    assert scanner._is_safe_path(12345) is False

# Vector 3: Tamper Detection & Critical Ignore Bypass (防篡改與惡意忽略檢測)
def test_zero_trust_critical_ignore_tamper_attempt(tmp_path):
    """Verify that attempting to suppress a CRITICAL finding using inline ignore is flagged as tamper."""
    scanner = Scanner(root_path=str(tmp_path))
    
    raw_findings = [{
        "file": "app.py",
        "line": 10,
        "name": "critical_hardcoded_private_key",
        "severity": "CRITICAL",
        "context": "private_key = '...' # ghostcheck-ignore",
        "message": "Found private key"
    }]
    
    processed = scanner._post_process(raw_findings)
    assert len(processed) == 1
    # Must tag tamper attempt and NOT drop the finding
    assert "TAMPER_ATTEMPT" in processed[0]["message"]
    assert processed[0]["severity"] == "CRITICAL"

# Vector 4: Offline Resilience (完全離線安全)
def test_zero_trust_offline_scanner_execution(tmp_path):
    """Verify that running Scanner in offline mode disables network calls and succeeds without network."""
    scanner = Scanner(root_path=str(tmp_path), offline=True)
    findings = scanner.scan()
    assert isinstance(findings, list)

# Vector 5: Unicode & Directional Formatting Obfuscation (Unicode 隱形字元與混淆)
def test_zero_trust_unicode_bidi_isolation(tmp_path):
    from ghostcheck.checks.context_inflation_detector import ContextInflationDetector
    detector = ContextInflationDetector()
    
    file_path = tmp_path / "trojan.py"
    # Consecutive zero-width Unicode injection
    trojan_line = "admin = False " + "\u200b" * 55 + "# Set admin = True"
    file_path.write_text(trojan_line, encoding="utf-8")
    
    findings = detector.scan([str(file_path)], None)
    assert any("invisible" in f.get("name", "") for f in findings)
