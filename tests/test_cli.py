import pytest
import sys
from ghostcheck.cli import main
from unittest.mock import patch

def test_cli_version(capsys):
    with patch('sys.argv', ['ghostcheck', '--version']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
    # argparse version prints to stderr in some versions, check both
    out, err = capsys.readouterr()
    assert "GhostCheck 0.2.0" in out or "GhostCheck 0.2.0" in err

def test_cli_help(capsys):
    with patch('sys.argv', ['ghostcheck', '--help']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
    out, err = capsys.readouterr()
    assert "GhostCheck: AI-Era Security Scanner" in out

def test_cli_demo(capsys):
    with patch('ghostcheck.demo.DemoRunner.run', return_value=0):
        with patch('sys.argv', ['ghostcheck', 'demo']):
            with pytest.raises(SystemExit) as e:
                main()
            assert e.value.code == 0
