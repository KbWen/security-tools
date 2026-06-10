import pytest
import os
import sys
from unittest.mock import patch
from ghostcheck.honeypot import GhostCheckHoneypotGenerator
from ghostcheck.cli import main

def test_honeypot_generator_direct(tmp_path):
    url = "http://canarytokens.com/test-url"
    success, msg = GhostCheckHoneypotGenerator.initialize(str(tmp_path), url)
    
    assert success is True
    
    # Check if files were created
    env_file = tmp_path / ".env.decoy"
    aws_file = tmp_path / "aws_credentials.decoy"
    rsa_file = tmp_path / "id_rsa.decoy"
    
    assert env_file.exists()
    assert aws_file.exists()
    assert rsa_file.exists()
    
    # Verify contents have CanaryToken URL
    env_content = env_file.read_text(encoding="utf-8")
    assert url in env_content
    assert "# GHOSTCHECK-HONEYPOT-DECOY" in env_content
    
    aws_content = aws_file.read_text(encoding="utf-8")
    assert url in aws_content
    
    rsa_content = rsa_file.read_text(encoding="utf-8")
    assert url in rsa_content

    # Check ignores
    gitignore = tmp_path / ".gitignore"
    ghostcheckignore = tmp_path / ".ghostcheckignore"
    
    assert gitignore.exists()
    assert ghostcheckignore.exists()
    
    gi_content = gitignore.read_text(encoding="utf-8")
    gci_content = ghostcheckignore.read_text(encoding="utf-8")
    
    assert ".env.decoy" in gi_content
    assert ".env.decoy" in gci_content

def test_honeypot_cli_init(tmp_path):
    url = "http://canarytokens.com/cli-test"
    target_dir = tmp_path / "cli_decoy"
    
    with patch('sys.argv', ['ghostcheck', 'honeypot', 'init', '--url', url, str(target_dir)]):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
        
    assert (target_dir / ".env.decoy").exists()
    assert (target_dir / ".gitignore").exists()
