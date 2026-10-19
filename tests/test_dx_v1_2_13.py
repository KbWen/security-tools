import os
import io
import json
import pytest
from unittest.mock import MagicMock, patch
import urllib.error

from ghostcheck.checks.hallucination import HallucinationChecker
from ghostcheck.checks.vuln_scanner import VulnScanner
from ghostcheck.checks.api_linter import APILinter
from ghostcheck.checks.entropy_scanner import EntropyScanner
from ghostcheck.reporters.console import ConsoleReporter
from ghostcheck.cli import main
import sys

# ==============================================================================
# AC1: Fast-Fail Circuit Breaker Tests
# ==============================================================================

def test_hallucination_circuit_breaker(tmp_path):
    checker = HallucinationChecker()
    checker.cache_file = str(tmp_path / "cache.json")
    checker.cache = {}
    checker.offline = False
    assert getattr(checker, "_consecutive_net_failures", 0) == 0

    reqs_content = "pkg1\npkg2\npkg3\npkg4\npkg5\n"

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network down")) as mock_urlopen:
        checker.check_requirements(reqs_content)

        # After 2 consecutive failures, circuit breaker sets offline=True
        # and skips the remaining 3 packages. Total calls should be exactly 2.
        assert mock_urlopen.call_count == 2
        assert checker.offline is True
        assert checker._consecutive_net_failures >= 2


def test_hallucination_circuit_breaker_resets_on_success(tmp_path):
    checker = HallucinationChecker()
    checker.cache_file = str(tmp_path / "cache.json")
    checker.cache = {}
    checker.offline = False

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.code = 200
    mock_resp.read.return_value = json.dumps({
        "info": {},
        "releases": {"1.0.0": [{"upload_time": "2020-01-01T00:00:00"}]}
    }).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", side_effect=[urllib.error.URLError("Network down"), mock_resp]) as mock_urlopen:
        # First call fails
        checker._check_package("PyPI", "pkg-fail-1")
        assert checker._consecutive_net_failures == 1
        assert checker.offline is False

        # Second call succeeds
        checker._check_package("PyPI", "pkg-success-2")
        assert checker._consecutive_net_failures == 0
        assert checker.offline is False
        assert mock_urlopen.call_count == 2


def test_vuln_scanner_circuit_breaker(tmp_path):
    import requests
    scanner = VulnScanner()
    scanner.cache_file = str(tmp_path / "osv_cache.json")
    scanner.cache = {}
    scanner.offline = False
    assert getattr(scanner, "_consecutive_net_failures", 0) == 0

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("p1==1.0\np2==1.0\np3==1.0\np4==1.0\np5==1.0\n", encoding="utf-8")

    with patch("requests.post", side_effect=requests.RequestException("Connection refused")) as mock_post:
        scanner.scan_file(str(req_file))

        # After 2 consecutive network failures, circuit breaker trips and sets offline=True
        assert mock_post.call_count == 2
        assert scanner.offline is True
        assert scanner._consecutive_net_failures >= 2


def test_vuln_scanner_circuit_breaker_resets_on_success(tmp_path):
    scanner = VulnScanner()
    scanner.cache_file = str(tmp_path / "osv_cache.json")
    scanner.cache = {}
    scanner.offline = False

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulns": []}

    import requests
    with patch("requests.post", side_effect=[requests.RequestException("Timeout"), mock_resp]) as mock_post:
        scanner._query_osv("pkg-a", "1.0", "PyPI")
        assert scanner._consecutive_net_failures == 1
        assert scanner.offline is False

        scanner._query_osv("pkg-b", "1.0", "PyPI")
        assert scanner._consecutive_net_failures == 0
        assert scanner.offline is False
        assert mock_post.call_count == 2


# ==============================================================================
# AC2: APILinter & EntropyScanner False-Positive Reduction Tests
# ==============================================================================

def test_api_linter_severities():
    linter = APILinter()
    cors_rule = next(r for r in linter.rules if r['name'] == 'api_cors_wildcard')
    csrf_rule = next(r for r in linter.rules if r['name'] == 'api_csrf_disabled')

    assert cors_rule['severity'] == "MEDIUM"
    assert csrf_rule['severity'] == "MEDIUM"


def test_api_linter_stateless_csrf_suppression():
    linter = APILinter()

    # (a) Stateless JWT file with CSRF disabled -> 0 findings
    jwt_content = """
    from flask import Flask
    import jwt

    app = Flask(__name__)
    app.config['CSRF_ENABLED'] = False
    JWT_SECRET = "super-secret"
    """
    findings_jwt = linter.scan_content("auth_jwt.py", jwt_content)
    assert len([f for f in findings_jwt if f['name'] == 'api_csrf_disabled']) == 0

    # (b) Stateful session file with CSRF disabled -> 1 finding with MEDIUM severity
    stateful_content = """
    from flask import Flask
    app = Flask(__name__)
    app.config['CSRF_ENABLED'] = False
    """
    findings_stateful = linter.scan_content("settings.py", stateful_content)
    csrf_findings = [f for f in findings_stateful if f['name'] == 'api_csrf_disabled']
    assert len(csrf_findings) == 1
    assert csrf_findings[0]['severity'] == "MEDIUM"

    # (c) CORS wildcard -> 1 finding with MEDIUM severity
    cors_content = """
    allow_origins = ["*"]
    """
    findings_cors = linter.scan_content("cors.py", cors_content)
    cors_findings = [f for f in findings_cors if f['name'] == 'api_cors_wildcard']
    assert len(cors_findings) == 1
    assert cors_findings[0]['severity'] == "MEDIUM"


def test_entropy_scanner_sri_hashes_ignored():
    scanner = EntropyScanner()
    content = """
    <script src="https://example.com/lib.js"
            integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
            crossorigin="anonymous"></script>
    <link rel="stylesheet" href="style.css"
          integrity="sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=">
    """
    findings = scanner.scan_content("index.html", content)
    assert len(findings) == 0


def test_entropy_scanner_data_uri_ignored():
    scanner = EntropyScanner()
    content = """
    const icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    """
    findings = scanner.scan_content("assets.js", content)
    assert len(findings) == 0


def test_entropy_scanner_multi_segment_paths_ignored():
    scanner = EntropyScanner()
    content = """
    app_path = "/usr/local/share/applications/my-custom-app"
    api_endpoint = "/api/v1/organizations/members/permissions"
    web_route = "/components/dashboard/analytics/charts"
    """
    findings = scanner.scan_content("routes.py", content)
    assert len(findings) == 0


def test_entropy_scanner_retains_real_secrets():
    scanner = EntropyScanner()
    # High entropy base64 secret without path/sri/data-uri markers
    content = """
    secret_key = "dGhpcy1pcy1hLXJlYWwtc2VjcmV0LWtleS0xMjM0NQ=="
    """
    findings = scanner.scan_content("config.py", content)
    assert len(findings) >= 1
    assert findings[0]['name'] == 'high_entropy_secret'


# ==============================================================================
# AC3: Quiet Mode CLI & ConsoleReporter Tests
# ==============================================================================

def test_console_reporter_quiet_mode_clean():
    stream = io.StringIO()
    reporter = ConsoleReporter(quiet=True, use_color=False)
    reporter.report([], stream=stream)
    assert stream.getvalue() == ""


def test_console_reporter_quiet_mode_hides_info_low():
    stream = io.StringIO()
    reporter = ConsoleReporter(quiet=True, use_color=False)
    findings = [
        {"severity": "INFO", "name": "info_rule", "file": "app.py", "line": 1, "message": "Info notice"},
        {"severity": "LOW", "name": "low_rule", "file": "app.py", "line": 2, "message": "Low advisory"},
    ]
    reporter.report(findings, stream=stream)
    # Only INFO and LOW findings -> quiet mode outputs nothing
    assert stream.getvalue() == ""


def test_console_reporter_quiet_mode_compact_on_actionable_findings():
    stream = io.StringIO()
    reporter = ConsoleReporter(quiet=True, use_color=False)
    findings = [
        {"severity": "INFO", "name": "info_rule", "file": "app.py", "line": 1, "message": "Info notice"},
        {"severity": "HIGH", "name": "hardcoded_secret", "file": "app.py", "line": 10, "message": "Secret found"},
    ]
    reporter.report(findings, stream=stream)
    output = stream.getvalue()
    assert "--- GhostCheck Scan Results ---" not in output
    assert "hardcoded_secret" in output
    assert "app.py:10: [HIGH] hardcoded_secret: Secret found" in output
    assert "info_rule" not in output


def test_cli_quiet_flag(monkeypatch, tmp_path, capsys):
    test_file = tmp_path / "clean.py"
    test_file.write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["ghostcheck", "scan", str(tmp_path), "-q"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Initializing scan" not in captured.out
    assert "Project Security Grade" not in captured.out
    assert captured.out.strip() == ""
