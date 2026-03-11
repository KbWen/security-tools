import pytest
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
    result = checker._check_pypi("ghost-package-123")
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
    result = checker._check_pypi("requests")
    assert result is None # Old package, no finding
