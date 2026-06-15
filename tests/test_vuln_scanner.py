import pytest
import json
from unittest.mock import patch, MagicMock
from ghostcheck.checks.vuln_scanner import VulnScanner

def test_vuln_scanner_basic(tmp_path):
    # Test requirements.txt scanning with mock OSV API
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n# comment\n\ninvalid_line\n", encoding="utf-8")
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_ok = True
    mock_response.json.return_value = {
        "vulns": [
            {"id": "GHSA-pip-1", "summary": "Vulnerability summary"}
        ]
    }
    
    with patch("requests.post", return_value=mock_response):
        scanner = VulnScanner(offline=False)
        assert scanner.name == "vulnscanner"
        assert scanner.description == "Scanner plugin for VulnScanner"
        
        findings = scanner.scan([str(req_file)], None)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "GHSA-pip-1"
        assert findings[0]["package"] == "requests"

def test_vuln_scanner_offline_or_none(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0", encoding="utf-8")
    
    # Test offline=True
    scanner_offline = VulnScanner(offline=True)
    findings = scanner_offline.scan([str(req_file)], None)
    assert len(findings) == 0

def test_vuln_scanner_api_errors(tmp_path, monkeypatch, capsys):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0", encoding="utf-8")
    
    # 1. Non-200 Status code
    mock_response = MagicMock()
    mock_response.status_code = 500
    with patch("requests.post", return_value=mock_response):
        scanner = VulnScanner()
        findings = scanner.scan([str(req_file)], None)
        assert len(findings) == 0
        
    # 2. RequestException under debug mode
    import requests
    def mock_post_fail(*args, **kwargs):
        raise requests.RequestException("Network timeout")
        
    monkeypatch.setenv("GHOSTCHECK_DEBUG", "1")
    with patch("requests.post", mock_post_fail):
        scanner = VulnScanner(proxy="http://myproxy:8080")
        assert scanner.proxy == "http://myproxy:8080"
        findings = scanner.scan([str(req_file)], None)
        assert len(findings) == 0
        
    captured = capsys.readouterr()
    assert "Vulnerability scan network error" in captured.out

def test_vuln_scanner_package_json(tmp_path):
    pkg_file = tmp_path / "package.json"
    
    # 1. Valid package.json
    pkg_data = {
        "dependencies": {
            "express": "^4.18.2"
        },
        "devDependencies": {
            "jest": "29.0.0"
        }
    }
    pkg_file.write_text(json.dumps(pkg_data), encoding="utf-8")
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulns": [
            {"id": "GHSA-npm-1", "summary": "NPM vulnerability"}
        ]
    }
    
    with patch("requests.post", return_value=mock_response):
        scanner = VulnScanner()
        findings = scanner.scan([str(pkg_file)], None)
        assert len(findings) == 2  # one for express, one for jest
        
    # 2. Malformed dependencies structure
    pkg_bad_data = {
        "dependencies": "not-a-dict",
        "devDependencies": {
            "jest": 1234  # not a string version
        }
    }
    pkg_file.write_text(json.dumps(pkg_bad_data), encoding="utf-8")
    with patch("requests.post", return_value=mock_response):
        scanner = VulnScanner()
        findings = scanner.scan([str(pkg_file)], None)
        assert len(findings) == 0
        
    # 3. Bad syntax JSON file (Exception in parsing)
    pkg_file.write_text("invalid json {", encoding="utf-8")
    scanner = VulnScanner()
    findings = scanner.scan([str(pkg_file)], None)
    assert len(findings) == 0
