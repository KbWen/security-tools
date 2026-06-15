import os
import pytest
from ghostcheck.scanner import Scanner

def test_is_self_scan_exempt():
    # Instantiate Scanner pointing to current directory
    scanner = Scanner(root_path=".", ignore_enabled=True)
    
    # 1. Test Git history findings (file_path is empty)
    # If the finding is 'ai_unreviewed_commit' and we are scanning our own repo (which we are, since "." contains src/ghostcheck)
    fnd_git = {"file": "", "name": "ai_unreviewed_commit"}
    assert scanner._is_self_scan_exempt(fnd_git) is True
    
    # Git history with other name shouldn't be exempted
    fnd_git_other = {"file": "", "name": "other_rule"}
    assert scanner._is_self_scan_exempt(fnd_git_other) is False
    
    # 2. Test Demo fixtures (contains src/ghostcheck/data/demo_fixtures/)
    fnd_demo = {"file": "src/ghostcheck/data/demo_fixtures/rules_demo.md", "name": "dangerous_system_command"}
    assert scanner._is_self_scan_exempt(fnd_demo) is True
    
    # 3. Test checkers (contains src/ghostcheck/checks/)
    # Exempted rule in checkers
    fnd_check_exempt = {"file": "src/ghostcheck/checks/ai_marker.py", "name": "hardcoded_identity_bypass"}
    assert scanner._is_self_scan_exempt(fnd_check_exempt) is True
    
    fnd_check_exempt_csrf = {"file": "src/ghostcheck/checks/api_linter.py", "name": "api_csrf_disabled"}
    assert scanner._is_self_scan_exempt(fnd_check_exempt_csrf) is True
    
    # Real secret in checkers should NOT be exempted
    fnd_check_secret = {"file": "src/ghostcheck/checks/ai_marker.py", "name": "OpenAI API Key"}
    assert scanner._is_self_scan_exempt(fnd_check_secret) is False
    
    # 4. Test high_entropy_secret with dummy placeholder
    fnd_entropy_dummy = {"file": "src/ghostcheck/checks/secrets.py", "name": "high_entropy_secret", "context": "abcdefghijklmnopqrstuvwxyz"}
    assert scanner._is_self_scan_exempt(fnd_entropy_dummy) is True
    
    # high_entropy_secret with real-looking key should NOT be exempted
    fnd_entropy_real = {"file": "src/ghostcheck/checks/secrets.py", "name": "high_entropy_secret", "context": "api_key = 'sk-proj-xyz'"}
    assert scanner._is_self_scan_exempt(fnd_entropy_real) is False

    # 5. Test utility files (init.py and config.py)
    fnd_init_loop = {"file": "src/ghostcheck/init.py", "name": "Missing Agentic Kill-Switch"}
    assert scanner._is_self_scan_exempt(fnd_init_loop) is True
    
    fnd_config_install = {"file": "src/ghostcheck/config.py", "name": "Silent Package Installation"}
    assert scanner._is_self_scan_exempt(fnd_config_install) is True
    
    fnd_config_privilege = {"file": "src/ghostcheck/config.py", "name": "Elevated Agent Privilege"}
    assert scanner._is_self_scan_exempt(fnd_config_privilege) is True
    
    # Other rules on utility files should NOT be exempted
    fnd_config_secret = {"file": "src/ghostcheck/config.py", "name": "OpenAI API Key"}
    assert scanner._is_self_scan_exempt(fnd_config_secret) is False
