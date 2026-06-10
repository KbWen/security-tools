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
    env_file = tmp_path / ".env.canary"
    aws_file = tmp_path / "aws_credentials.canary"
    rsa_file = tmp_path / "id_rsa.canary"
    
    assert env_file.exists()
    assert aws_file.exists()
    assert rsa_file.exists()
    
    # Verify contents have CanaryToken URL
    env_content = env_file.read_text(encoding="utf-8")
    assert url in env_content
    assert "# GHOSTCHECK-HONEYPOT-CANARY" in env_content
    
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
    
    assert ".env.canary" in gi_content
    assert ".env.canary" in gci_content

def test_honeypot_cli_direct(tmp_path):
    url = "http://canarytokens.com/cli-test"
    target_dir = tmp_path / "cli_canary"
    
    with patch('sys.argv', ['ghostcheck', 'honeypot', '--url', url, str(target_dir)]):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
        
    assert (target_dir / ".env.canary").exists()
    assert (target_dir / ".gitignore").exists()

def test_honeypot_cli_config_fallback(tmp_path):
    # Setup ghostcheck.toml with canary_url in tmp_path
    config_content = """
[honeypot]
canary_url = "http://canarytokens.com/config-fallback-test"
"""
    # Write config file to project root (tmp_path)
    with open(tmp_path / "ghostcheck.toml", "w") as f:
        f.write(config_content)
        
    # We run honeypot directly without --url CLI arg
    target_dir = tmp_path / "config_canary"
    
    # We patch project_root lookup in GhostCheckConfig.__init__ or we patch config lookup
    from ghostcheck.config import GhostCheckConfig
    orig_init = GhostCheckConfig.__init__
    
    def mock_init(self, project_root):
        orig_init(self, str(tmp_path))
        
    with patch.object(GhostCheckConfig, '__init__', mock_init):
        with patch('sys.argv', ['ghostcheck', 'honeypot', str(target_dir)]):
            with pytest.raises(SystemExit) as e:
                main()
            assert e.value.code == 0
            
    assert (target_dir / ".env.canary").exists()
    # Check if correct fallback url is written
    env_content = (target_dir / ".env.canary").read_text(encoding="utf-8")
    assert "http://canarytokens.com/config-fallback-test" in env_content
