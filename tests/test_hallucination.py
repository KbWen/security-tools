import pytest
import json
from unittest.mock import patch, MagicMock
from ghostcheck.checks.hallucination import HallucinationChecker
import urllib.error

def test_parse_requirements():
    checker = HallucinationChecker()
    content = "requests==2.25.1\n# comment\nflask\n  django  \n"
    pkgs = checker._parse_requirements(content)
    assert pkgs == ["requests", "flask", "django"]

@patch('urllib.request.urlopen')
def test_check_pypi_not_found(mock_urlopen):
    # Mock a 404 error
    mock_urlopen.side_effect = urllib.error.HTTPError("url", 404, "Not Found", {}, None)
    checker = HallucinationChecker()
    result = checker._check_pypi_online("ghost-package-123")
    assert result['severity'] == "CRITICAL"
    assert "does not exist" in result['message']

@patch('urllib.request.urlopen')
def test_check_pypi_success(mock_urlopen):
    # Mock a successful response
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"info": {}, "releases": {"1.0.0": [{"upload_time": "2020-01-01T00:00:00"}]}}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    checker = HallucinationChecker()
    result = checker._check_pypi_online("requests")
    assert result is None # Old package, no finding

@patch('urllib.request.urlopen')
def test_check_pypi_timeout(mock_urlopen):
    # Mock a timeout
    mock_urlopen.side_effect = TimeoutError("Connection timed out")
    checker = HallucinationChecker()
    result = checker._check_pypi_online("any-pkg")
    assert result is None # Should handle gracefully

@patch('urllib.request.urlopen')
def test_check_pypi_malformed_json(mock_urlopen):
    # Mock malformed JSON
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"info": { "invalid": json } }'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    checker = HallucinationChecker()
    result = checker._check_pypi_online("any-pkg")
    print(f"DEBUG MALFORMED: {result}")
    assert result is None # Should handle gracefully

@patch('urllib.request.urlopen')
def test_check_pypi_new_package(mock_urlopen):
    # Mock a very new package (less than 30 days)
    mock_response = MagicMock()
    # Mock date: 10 days ago
    from datetime import datetime, timedelta
    ten_days_ago = (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%dT%H:%M:%S')
    mock_response.read.return_value = json.dumps({
        "info": {},
        "releases": {"1.0.0": [{"upload_time": ten_days_ago}]}
    }).encode()
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    checker = HallucinationChecker()
    # We call _check_pypi_online directly to bypass cache
    result = checker._check_pypi_online("new-pkg")
    print(f"DEBUG NEW PKG: {result}")
    assert result is not None
    assert result['severity'] == "HIGH"
    assert "very new" in result['message']

def test_empty_requirements():
    checker = HallucinationChecker()
    findings = checker.check_requirements("")
    assert findings == []
