import os
import json
import pytest
from unittest.mock import patch, MagicMock
import urllib.error

from ghostcheck.checks.hallucination import HallucinationChecker
from ghostcheck.checks.vuln_scanner import VulnScanner
from ghostcheck.checks.shadow_ai import ShadowAIDetector
from ghostcheck.checks.lethal_trifecta_detector import LethalTrifectaDetector
from ghostcheck.checks.killswitch_auditor import KillSwitchAuditor
from ghostcheck.checks.tamper_auditor import TamperAuditor
from ghostcheck.checks.ai_marker import AIMarker
from ghostcheck.config import GhostCheckConfig
from ghostcheck.scanner import Scanner
from ghostcheck.reporters.console import ConsoleReporter
import ghostcheck.cli as cli


# ==============================================================================
# AC1: HallucinationChecker Cache Poisoning Fix & VulnScanner Cache
# ==============================================================================

def test_hallucination_cache_poisoning_prevented_on_network_error(tmp_path):
    """When a network error occurs, do NOT cache 'OK' in self.cache."""
    checker = HallucinationChecker()
    checker.cache_dir = str(tmp_path)
    checker.cache_file = str(tmp_path / "hallucination.json")
    checker.cache = {}

    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.URLError("DNS lookup failed")
        res, network_called = checker._check_package("PyPI", "unreachable-pkg-xyz")
        assert res is None
        # Must NOT be in cache
        assert "PyPI:unreachable-pkg-xyz" not in checker.cache


def test_hallucination_cache_stores_only_confirmed_200_and_404(tmp_path):
    """HTTP 200 caches 'OK' (or age finding); HTTP 404 caches the finding dict."""
    checker = HallucinationChecker()
    checker.cache_dir = str(tmp_path)
    checker.cache_file = str(tmp_path / "hallucination.json")
    checker.cache = {}

    # 1. 200 OK -> caches 'OK'
    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.code = 200
        mock_resp.read.return_value = json.dumps({
            "info": {},
            "releases": {"1.0.0": [{"upload_time": "2020-01-01T00:00:00"}]}
        }).encode()
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res, _ = checker._check_package("PyPI", "requests")
        assert res is None
        assert checker.cache.get("PyPI:requests", {}).get("data") == "OK"

    # 2. 404 Not Found -> caches finding dict
    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.HTTPError("url", 404, "Not Found", {}, None)
        res, _ = checker._check_package("PyPI", "definitely-fake-pkg-12345")
        assert res is not None
        assert res["severity"] == "CRITICAL"
        cached_entry = checker.cache.get("PyPI:definitely-fake-pkg-12345", {}).get("data")
        assert isinstance(cached_entry, dict)
        assert cached_entry["severity"] == "CRITICAL"


def test_hallucination_crates_support_and_no_poison(tmp_path):
    """Crates registry check does not poison cache on error."""
    checker = HallucinationChecker()
    checker.cache_dir = str(tmp_path)
    checker.cache_file = str(tmp_path / "hallucination.json")
    checker.cache = {}

    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_urlopen.side_effect = TimeoutError("timed out")
        res, _ = checker._check_package("crates", "tokio-fake-nonexistent")
        assert res is None
        assert "crates:tokio-fake-nonexistent" not in checker.cache


def test_hallucination_checker_no_time_sleep():
    """Verify time.sleep is not invoked in HallucinationChecker."""
    checker = HallucinationChecker()
    with patch('time.sleep') as mock_sleep, \
         patch.object(checker, '_check_package', return_value=(None, True)):
        checker.check_requirements("requests==2.25.1\nflask\n")
        checker.check_package_json('{"dependencies": {"express": "^4.18.2"}}')
        assert mock_sleep.call_count == 0, "time.sleep must not be called in HallucinationChecker"


def test_vuln_scanner_caches_osv_responses_locally(tmp_path):
    """VulnScanner caches OSV responses locally with 24h TTL and avoids re-querying."""
    scanner = VulnScanner()
    scanner.cache_dir = str(tmp_path)
    scanner.cache_file = str(tmp_path / "osv_cache.json")
    scanner.cache = {}

    with patch('requests.post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulns": [{"id": "GHSA-1234", "summary": "Test Vuln"}]}
        mock_post.return_value = mock_resp

        res1 = scanner._query_osv("vulnerable-pkg", "1.0.0", "PyPI")
        assert res1 == {"vulns": [{"id": "GHSA-1234", "summary": "Test Vuln"}]}
        assert mock_post.call_count == 1

        # Second call should use cache
        res2 = scanner._query_osv("vulnerable-pkg", "1.0.0", "PyPI")
        assert res2 == res1
        assert mock_post.call_count == 1  # Not called again


def test_vuln_scanner_does_not_cache_network_errors(tmp_path):
    """VulnScanner does not cache OSV network errors."""
    import requests
    scanner = VulnScanner()
    scanner.cache_dir = str(tmp_path)
    scanner.cache_file = str(tmp_path / "osv_cache.json")
    scanner.cache = {}

    with patch('requests.post') as mock_post:
        mock_post.side_effect = requests.RequestException("Network unreachable")
        res = scanner._query_osv("some-pkg", "1.0.0", "PyPI")
        assert res is None
        assert "PyPI:some-pkg:1.0.0" not in scanner.cache


# ==============================================================================
# AC2: --fail-on Default is HIGH
# ==============================================================================

def test_cli_fail_on_default_is_high():
    """Default --fail-on is HIGH: INFO/LOW/MEDIUM findings exit 0, HIGH/CRITICAL exit 1."""
    # 1. MEDIUM finding alone exits 0 with default --fail-on
    with patch('sys.argv', ['ghostcheck', 'scan']), \
         patch('ghostcheck.scanner.Scanner.scan') as mock_scan:
        mock_scan.return_value = [
            {"name": "medium_issue", "severity": "MEDIUM", "file": "app.py", "line": 1, "context": "x = 1"}
        ]
        with pytest.raises(SystemExit) as e:
            cli.main()
        assert e.value.code == 0

    # 2. HIGH finding exits 1 with default --fail-on
    with patch('sys.argv', ['ghostcheck', 'scan']), \
         patch('ghostcheck.scanner.Scanner.scan') as mock_scan:
        mock_scan.return_value = [
            {"name": "high_issue", "severity": "HIGH", "file": "app.py", "line": 1, "context": "x = 1"}
        ]
        with pytest.raises(SystemExit) as e:
            cli.main()
        assert e.value.code == 1

    # 3. Explicit --fail-on MEDIUM exits 1 on MEDIUM finding
    with patch('sys.argv', ['ghostcheck', 'scan', '--fail-on', 'MEDIUM']), \
         patch('ghostcheck.scanner.Scanner.scan') as mock_scan:
        mock_scan.return_value = [
            {"name": "medium_issue", "severity": "MEDIUM", "file": "app.py", "line": 1, "context": "x = 1"}
        ]
        with pytest.raises(SystemExit) as e:
            cli.main()
        assert e.value.code == 1


# ==============================================================================
# AC3: disabled_rules Config & Non-Punitive # ghostcheck-ignore
# ==============================================================================

def test_ghostcheck_config_disabled_rules_support(tmp_path):
    """GhostCheckConfig supports disabled_rules list."""
    config_file = tmp_path / "ghostcheck.toml"
    config_file.write_text('disabled_rules = ["hardcoded_secret", "dangerous_system_command"]\n')

    cfg = GhostCheckConfig(str(tmp_path))
    assert "hardcoded_secret" in cfg.disabled_rules
    assert "dangerous_system_command" in cfg.disabled_rules


def test_scanner_post_process_filters_disabled_rules(tmp_path):
    """Scanner._post_process filters out findings matching config.disabled_rules."""
    cfg = GhostCheckConfig(str(tmp_path))
    cfg.config['disabled_rules'] = ["hardcoded_secret", "dangerous_system_command"]

    scanner = Scanner(str(tmp_path), config=cfg)
    raw_findings = [
        {"name": "hardcoded_secret", "severity": "HIGH", "file": "app.py", "line": 10},
        {"name": "other_issue", "rule_id": "DANGEROUS_SYSTEM_COMMAND", "severity": "CRITICAL", "file": "app.py", "line": 20},
        {"name": "legitimate_issue", "rule_id": "GSA-01", "severity": "HIGH", "file": "app.py", "line": 30},
    ]
    processed = scanner._post_process(raw_findings)
    assert len(processed) == 1
    assert processed[0]["name"] == "legitimate_issue"


def test_ghostcheck_ignore_suppresses_critical_without_punishment(tmp_path):
    """# ghostcheck-ignore suppresses CRITICAL findings without TAMPER_ATTEMPT punishment."""
    scanner = Scanner(str(tmp_path))
    raw_findings = [{
        "file": "app.py",
        "line": 10,
        "name": "critical_hardcoded_private_key",
        "severity": "CRITICAL",
        "context": "private_key = '...' # ghostcheck-ignore",
        "message": "Found private key"
    }]
    processed = scanner._post_process(raw_findings)
    assert len(processed) == 0, "CRITICAL finding with # ghostcheck-ignore must be cleanly suppressed"


def test_ghostcheck_ignore_targeted_syntax(tmp_path):
    """# ghostcheck-ignore: <rule_name> suppresses only the targeted rule."""
    scanner = Scanner(str(tmp_path))

    # Targeted ignore matches
    findings_matched = scanner._post_process([{
        "file": "app.py",
        "line": 10,
        "name": "hardcoded_secret",
        "severity": "HIGH",
        "context": "x = 'sec' # ghostcheck-ignore: hardcoded_secret",
        "message": "secret found"
    }])
    assert len(findings_matched) == 0

    # Targeted ignore does NOT match a different rule
    findings_unmatched = scanner._post_process([{
        "file": "app.py",
        "line": 10,
        "name": "dangerous_system_command",
        "severity": "HIGH",
        "context": "x = 'sec' # ghostcheck-ignore: hardcoded_secret",
        "message": "dangerous command"
    }])
    assert len(findings_unmatched) == 1


def test_tamper_auditor_no_longer_emits_excessive_ignores():
    """TamperAuditor no longer emits Evasion: Excessive Ignores for >5 ignores."""
    auditor = TamperAuditor()
    content = "\n".join([f"# ghostcheck-ignore rule_{i}" for i in range(10)])
    findings = auditor.scan_file("test.py", content)
    assert not any("Excessive Ignores" in f.get("name", "") for f in findings)


# ==============================================================================
# AC4: --compact Single-Line Console Output
# ==============================================================================

def test_console_reporter_compact_output(capsys):
    """ConsoleReporter with compact=True prints each finding on a single clean line."""
    reporter = ConsoleReporter(use_color=False, compact=True)
    findings = [
        {
            "file": "src/app.py",
            "line": 42,
            "severity": "HIGH",
            "name": "hardcoded_api_key",
            "message": "Found sensitive API key."
        },
        {
            "file": "src/utils.py",
            "line": 10,
            "severity": "CRITICAL",
            "name": "eval_injection",
            "message": "Arbitrary code execution."
        }
    ]
    reporter.report(findings)
    out, _ = capsys.readouterr()
    lines = [l.strip() for l in out.strip().splitlines() if l.strip()]

    # Check format: {file}:{line}: [{severity}] {name}: {message}
    assert any("src/app.py:42: [HIGH] hardcoded_api_key: Found sensitive API key." in l for l in lines)
    assert any("src/utils.py:10: [CRITICAL] eval_injection: Arbitrary code execution." in l for l in lines)
    # Check 1-line summary at the end
    assert any("Summary" in l or "CRITICAL: 1" in l for l in lines)


# ==============================================================================
# AC5: False-Positive Reduction Across 5 Noisy Checkers
# ==============================================================================

def test_shadow_ai_default_does_not_flag_standard_sdks():
    """When blocked_sdks is empty, do NOT flag standard AI SDK imports."""
    detector = ShadowAIDetector()  # No config provided
    content = "import openai\nimport anthropic\nimport langchain\n"
    findings = detector.scan_file("agent.py", content)
    assert len(findings) == 0, "Default configuration must not flag standard AI SDKs as shadow AI"


def test_shadow_ai_flags_when_blocked_sdks_configured():
    """When blocked_sdks is explicitly configured, flag matched SDKs."""
    config = {
        "shadow_ai": {
            "blocked_sdks": ["openai"]
        }
    }
    detector = ShadowAIDetector(config=config)
    content = "import openai\nimport anthropic\n"
    findings = detector.scan_file("agent.py", content)
    assert len(findings) == 1
    assert any("openai" in f.get("message", "").lower() or f.get("name") == "unauthorized_ai_sdk_python" for f in findings)


def test_lethal_trifecta_does_not_flag_generic_run_or_call(tmp_path):
    """Generic .run() or .call() on arbitrary objects is NOT treated as command execution."""
    checker = LethalTrifectaDetector()
    f = tmp_path / "normal_pipeline.py"
    f.write_text("""
def execute_pipeline(user_query):
    with open("data.txt") as fp:
        data = fp.read()
    pipeline.run(user_query) # Arbitrary object call, NOT subprocess.run!
    task.call()
""")
    findings = checker.scan([str(f)], config=None)
    assert not any(fnd["name"] == "Lethal Trifecta Detected" for fnd in findings)


def test_killswitch_auditor_does_not_flag_non_agentic_recursion(tmp_path):
    """Normal data structure/tree recursion without AI/network keywords is NOT flagged."""
    auditor = KillSwitchAuditor()
    f = tmp_path / "ast_walk.py"
    f.write_text("""
def walk(node):
    if not node:
        return
    for child in node.children:
        walk(child)
""")
    findings = auditor.scan([str(f)], None)
    assert not any(f["name"] == "Missing Recursive Kill-Switch" for f in findings)


def test_killswitch_auditor_flags_agentic_recursion_without_limit(tmp_path):
    """Recursive agent function with LLM/network indicators without limit IS flagged."""
    auditor = KillSwitchAuditor()
    f = tmp_path / "agent_loop.py"
    f.write_text("""
def agent_step():
    llm.invoke("plan next step")
    agent_step()
""")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Recursive Kill-Switch" for f in findings)


def test_ai_marker_unreviewed_commit_severity_is_info():
    """AIMarker downgrades ai_unreviewed_commit severity to INFO."""
    scanner = AIMarker()
    with patch.object(scanner, '_get_secure_git', return_value="git"), \
         patch('subprocess.run') as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = (
            "c1c1c1c1\x1fnoreply@anthropic.com\x1ffeat: auto commit\n\n"
            "Co-authored-by: Claude <noreply@anthropic.com>\x1e"
        ).encode('utf-8')
        mock_run.return_value = mock_proc

        findings = scanner.scan_git_history()
        assert len(findings) == 1
        assert findings[0]["name"] == "ai_unreviewed_commit"
        assert findings[0]["severity"] == "INFO"


def test_silent_installer_exempts_pip_bootstrap_upgrade(tmp_path):
    """Standard 'pip install --upgrade pip setuptools wheel' in scripts is not flagged as unpinned hijack."""
    from ghostcheck.checks.silent_installer import SilentInstaller
    auditor = SilentInstaller()
    f = tmp_path / "ci_bootstrap.sh"
    f.write_text("#!/bin/bash\npython -m pip install --upgrade pip setuptools wheel\n", encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert len(findings) == 0

