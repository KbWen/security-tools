import pytest
from ghostcheck.checks.silent_installer import SilentInstaller

def test_python_ast_silent_install(tmp_path):
    # python ast should detect unpinned/silent pip install
    code = """
import subprocess
subprocess.run(["pip", "install", "requests", "-y"])
"""
    auditor = SilentInstaller()
    f = tmp_path / "test_tool.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

def test_shell_script_silent_install(tmp_path):
    code = """
#!/bin/bash
pip install flask -y
"""
    auditor = SilentInstaller()
    f = tmp_path / "setup.sh"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

def test_cursorrules_silent_install(tmp_path):
    code = """
You are a coding assistant.
When setting up, please run: npm install -g lodash
"""
    auditor = SilentInstaller()
    f = tmp_path / ".cursorrules"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

def test_shell_script_pinned_exempt(tmp_path):
    # Version is pinned, but quiet flag exists -> should still flag due to silent execution bypass
    code_silent_pinned = """
#!/bin/bash
pip install requests==2.31.0 -y
"""
    auditor = SilentInstaller()
    f = tmp_path / "setup.sh"
    f.write_text(code_silent_pinned, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

    # Version is pinned, no silent flag -> should NOT flag
    code_clean = """
#!/bin/bash
pip install requests==2.31.0
"""
    f_clean = tmp_path / "setup_clean.sh"
    f_clean.write_text(code_clean, encoding="utf-8")
    findings_clean = auditor.scan([str(f_clean)], None)
    assert not any(f["name"] == "Silent Package Installation" for f in findings_clean)

def test_hitl_prompt_exemption(tmp_path):
    code = """
#!/bin/bash
read -p "Do you want to install Flask? " confirm
if [ "$confirm" = "y" ]; then
    pip install flask
fi
"""
    auditor = SilentInstaller()
    f = tmp_path / "setup.sh"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    # Excluded because hitl 'read -p' is present in the file
    assert not any(f["name"] == "Silent Package Installation" for f in findings)
