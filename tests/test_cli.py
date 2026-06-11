import pytest
import sys
from ghostcheck.cli import main
from unittest.mock import patch

from ghostcheck import __version__

def test_cli_version(capsys):
    with patch('sys.argv', ['ghostcheck', '--version']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
    # argparse version prints to stderr in some versions, check both
    out, err = capsys.readouterr()
    assert f"GhostCheck {__version__}" in out or f"GhostCheck {__version__}" in err

def test_cli_help(capsys):
    with patch('sys.argv', ['ghostcheck', '--help']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
    out, err = capsys.readouterr()
    assert "GhostCheck: AI-Era Security Scanner" in out


def test_config_timeout():
    from ghostcheck.config import GhostCheckConfig
    
    # 1. Valid timeout
    class Args:
        timeout = 42
    config = GhostCheckConfig(".")
    config.update_from_args(Args())
    assert config.get("timeout") == 42
    
    # 2. None timeout (should fallback to default 10)
    class ArgsNone:
        timeout = None
    config2 = GhostCheckConfig(".")
    config2.update_from_args(ArgsNone())
    assert config2.get("timeout") == 10
    
    # 3. Invalid timeout (negative or zero)
    class ArgsZero:
        timeout = 0
    config3 = GhostCheckConfig(".")
    with pytest.raises(ValueError, match="Timeout must be a positive integer"):
        config3.update_from_args(ArgsZero())
        
    class ArgsNeg:
        timeout = -5
    config4 = GhostCheckConfig(".")
    with pytest.raises(ValueError, match="Timeout must be a positive integer"):
        config4.update_from_args(ArgsNeg())


def test_cli_version_command(capsys):
    with patch('sys.argv', ['ghostcheck', 'version']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
    out, err = capsys.readouterr()
    assert f"GhostCheck version: {__version__}" in out
    assert "Python version:" in out
    assert "Platform:" in out


def test_cli_check_rules(capsys):
    from unittest.mock import MagicMock
    with patch('sys.argv', ['ghostcheck', 'check-rules']), \
         patch('ghostcheck.scanner.Scanner.scan_rules') as mock_scan_rules:
        mock_scan_rules.return_value = [
            {"name": "risky_rule", "severity": "HIGH", "suggestion": "Malicious rules found", "file": ".cursorrules", "line": 5}
        ]
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 1
    out, err = capsys.readouterr()
    assert "risky_rule" in out or "risky_rule" in err
    assert "Malicious rules found" in out or "Malicious rules found" in err
