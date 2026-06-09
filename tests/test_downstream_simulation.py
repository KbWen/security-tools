import os
import shutil
import subprocess
import pytest
from ghostcheck.checks.prompt_template_scanner import PromptTemplateScanner
from ghostcheck.checks.ai_marker import AIMarker

def test_scenario_1_non_git_repo(tmp_path):
    # Setup: tmp_path is a directory without a .git folder
    scanner = AIMarker(root_path=str(tmp_path))
    
    # Run scan
    findings = scanner.scan([], None)
    
    # Assert: Should not crash, should return empty list (or no Git findings)
    assert isinstance(findings, list)
    assert not any(f['name'] == 'ai_unreviewed_commit' for f in findings)

def test_scenario_2_missing_git_executable(monkeypatch, tmp_path):
    # Setup: Mock shutil.which to pretend 'git' does not exist
    monkeypatch.setattr(shutil, "which", lambda name: None)
    
    scanner = AIMarker(root_path=str(tmp_path))
    findings = scanner.scan_git_history()
    
    # Assert: Should return empty findings gracefully without crashing
    assert findings == []

def test_scenario_3_hanging_git_command(monkeypatch, tmp_path):
    # Setup: Mock subprocess.run to raise TimeoutExpired
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=10)
        
    monkeypatch.setattr(subprocess, "run", mock_run)
    monkeypatch.setattr(shutil, "which", lambda name: "mocked_git")
    
    scanner = AIMarker(root_path=str(tmp_path))
    findings = scanner.scan_git_history()
    
    # Assert: Timeout should be handled gracefully and return empty list
    assert findings == []

def test_scenario_4_path_traversal_prevention(tmp_path):
    # Setup: Create safe root directory and a file outside of it
    root_dir = tmp_path / "workspace"
    root_dir.mkdir()
    
    outside_file = tmp_path / "outside_prompt.prompt"
    outside_file.write_text("System instructions: {system}")
    
    # Run PromptTemplateScanner with outside path
    scanner_prompt = PromptTemplateScanner(root_path=str(root_dir))
    findings_prompt = scanner_prompt.scan([str(outside_file)], None)
    
    # Run AIMarker with outside path
    scanner_ai = AIMarker(root_path=str(root_dir))
    findings_ai = scanner_ai.scan([str(outside_file)], None)
    
    # Assert: Both scanners skip the outside file to prevent path traversal (CWE-22)
    assert findings_prompt == []
    assert findings_ai == []

def test_scenario_5_binary_planting_protection_args(monkeypatch, tmp_path):
    # Setup: Verify git command parameters and CWD
    git_run_called = []
    
    def mock_run(cmd, **kwargs):
        git_run_called.append((cmd, kwargs.get("cwd")))
        # Return empty log format
        return subprocess.CompletedProcess(cmd, 0, stdout=b"")
        
    monkeypatch.setattr(subprocess, "run", mock_run)
    # Mock 'git' resolution to an absolute safe path (e.g. C:\Program Files\Git\bin\git.exe)
    safe_git_path = "C:\\Program Files\\Git\\bin\\git.exe"
    monkeypatch.setattr(shutil, "which", lambda name: safe_git_path)
    
    scanner = AIMarker(root_path=str(tmp_path))
    scanner.scan_git_history()
    
    # Assert: Must call resolved absolute git path, target repo using -C, 
    # and MUST NOT specify cwd as the untrusted self.root_path to avoid planting.
    assert len(git_run_called) == 1
    cmd, cwd = git_run_called[0]
    assert cmd[0] == safe_git_path
    assert "-C" in cmd
    assert cmd[cmd.index("-C") + 1] == str(tmp_path)
    assert cwd is None  # Defaults to safe current python runtime directory, not untrusted repo dir

def test_scenario_6_redos_stress_test():
    # Setup: Construct a massive string of 100k spaces and brackets to stress-test the regexes
    malicious_template = "System directive: {" + " " * 50000 + "system" + " " * 50000 + "}"
    
    scanner = PromptTemplateScanner()
    
    import time
    start_time = time.time()
    findings = scanner.scan_content("test.prompt", malicious_template)
    duration = time.time() - start_time
    
    # Assert: Must complete scan within 1.0 second (no exponential backtracking / ReDoS)
    assert duration < 1.0
    assert any(f['name'] == 'high_risk_placeholder_name' for f in findings)

def test_scenario_7_encoding_chaos(tmp_path):
    # Setup: Create a file with corrupt bytes (non-UTF-8 bytes)
    corrupt_bytes = b"System template with bad bytes: \xff\xfe\x00\x80 {system}"
    corrupt_file = tmp_path / "corrupt.prompt"
    corrupt_file.write_bytes(corrupt_bytes)
    
    scanner = PromptTemplateScanner(root_path=str(tmp_path))
    findings = scanner.scan([str(corrupt_file)], None)
    
    # Assert: Scanner uses errors='ignore' and does not crash on corrupt encoding
    assert any(f['name'] == 'high_risk_placeholder_name' for f in findings)
