import os
import json
import pytest
from ghostcheck.scanner import Scanner
from ghostcheck.config import GhostCheckConfig

def test_robust_baseline_line_shift(tmp_path):
    # Setup: a file with a secret (must be long enough for patterns)
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    secret_file = project_dir / "secret.py"
    secret_val = "sk-antigravity-" + "x" * 32 
    secret_file.write_text(f'API_KEY = "{secret_val}"\nprint("Hello")')
    
    config = GhostCheckConfig(str(project_dir))
    scanner = Scanner(str(project_dir), config=config)
    
    # 1. First scan to get the finding
    findings = scanner.scan()
    print(f"\nScan 1 finding: {findings[0] if findings else 'None'}")
    assert len(findings) > 0
    
    # 2. Create baseline
    baseline_path = project_dir / ".ghostcheckbaseline"
    with open(baseline_path, "w") as f:
        json.dump({"findings": findings}, f)
        
    # 3. Modify file: shift line numbers
    secret_file.write_text(f'# New comment at top\n# Another\nAPI_KEY = "{secret_val}"\nprint("Hello")')
    
    # 4. Scan again with baseline
    scanner_new = Scanner(str(project_dir), config=config, baseline_path=str(baseline_path))
    findings_new = scanner_new.scan()
    print(f"Scan 2 findings (should be 0): {findings_new}")
    
    assert len(findings_new) == 0

def test_robust_baseline_content_change(tmp_path):
    # Setup
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    secret_file = project_dir / "secret.py"
    secret_orig = "sk-antigravity-ORIGINAL-" + "x" * 20
    secret_file.write_text(f'API_KEY = "{secret_orig}"\n')
    
    config = GhostCheckConfig(str(project_dir))
    scanner = Scanner(str(project_dir), config=config)
    
    findings = scanner.scan()
    assert len(findings) > 0
    baseline_path = project_dir / ".ghostcheckbaseline"
    with open(baseline_path, "w") as f:
        json.dump({"findings": findings}, f)
        
    # Modify secret value AND shift line
    secret_new = "sk-antigravity-NEW-VALUE-" + "y" * 20
    secret_file.write_text(f'# Shifting line\nAPI_KEY = "{secret_new}"\n')
    
    scanner_new = Scanner(str(project_dir), config=config, baseline_path=str(baseline_path))
    findings_new = scanner_new.scan()
    print(f"Scan 3 findings (should be >0): {findings_new}")
    
    assert len(findings_new) > 0


