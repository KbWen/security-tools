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

def test_hitl_comment_bypass_prevented(tmp_path):
    # Security bypass: placing '# input()' should NOT disable scanning for npm install
    code = """# input()
npm install express
"""
    auditor = SilentInstaller()
    f = tmp_path / "setup.sh"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

def test_ast_eval_exec_install(tmp_path):
    # Dynamic eval/exec installation: fallback text-based regex should catch it
    code = """eval("pip install flask -y")
"""
    auditor = SilentInstaller()
    f = tmp_path / "setup.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

def test_ast_getattr_obfuscation(tmp_path):
    # Reflection bypass: fallback text-based regex should catch it
    code = """getattr(subprocess, "run")("pip install flask -y")
"""
    auditor = SilentInstaller()
    f = tmp_path / "setup.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

def test_python_complex_args_joined_str(tmp_path):
    # ast.JoinedStr, ast.BinOp, ast.List
    code = """import subprocess
pkg = "flask"
# BinOp
subprocess.run("pip install " + pkg + " -y")
# JoinedStr
subprocess.run(f"pip install {pkg} -y")
# List parameter
subprocess.run(["pip", "install", pkg, "-y"])
"""
    auditor = SilentInstaller()
    f = tmp_path / "setup.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert len(findings) >= 3

def test_cargo_go_unpinned(tmp_path):
    # Cargo install missing --version
    code_cargo = "cargo install ripgrep"
    # Go get missing @
    code_go = "go get github.com/gin-gonic/gin"
    # Grouped short flags
    code_pip = "pip install -qy requests"
    
    auditor = SilentInstaller()
    
    f1 = tmp_path / "setup_cargo.sh"
    f1.write_text(code_cargo, encoding="utf-8")
    findings_cargo = auditor.scan([str(f1)], None)
    assert any(f["name"] == "Silent Package Installation" and "pinned" in f["message"] for f in findings_cargo)
    
    f2 = tmp_path / "setup_go.sh"
    f2.write_text(code_go, encoding="utf-8")
    findings_go = auditor.scan([str(f2)], None)
    assert any(f["name"] == "Silent Package Installation" and "pinned" in f["message"] for f in findings_go)
    
    f3 = tmp_path / "setup_pip.sh"
    f3.write_text(code_pip, encoding="utf-8")
    findings_pip = auditor.scan([str(f3)], None)
    assert any(f["name"] == "Silent Package Installation" and "silent" in f["message"] for f in findings_pip)

def test_python_syntax_error_fallback(tmp_path):
    # Syntax error Python file should fallback to text-based regex scan
    code = """import subprocess
subprocess.run("pip install flask -y" # missing closing parenthesis
"""
    auditor = SilentInstaller()
    f = tmp_path / "bad_syntax.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings)

def test_visitor_imports_and_assign(tmp_path):
    # Test Import/ImportFrom aliases and variable assignments
    code = """import subprocess as sub
from subprocess import run as sub_run

cmd = ["pip", "install", "flask", "-y"]
sub.run(cmd)
sub_run(cmd)
"""
    auditor = SilentInstaller()
    f = tmp_path / "alias.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert len(findings) >= 2


def test_hitl_bypass_hardening(tmp_path):
    # Verify that writing 'input(' in comments, docstrings, or string literals does not bypass silent installer scanning
    
    # Case 1: python docstring containing input()
    code_docstring = """
    '''
    input('This is a docstring bypass attempt')
    '''
    import subprocess
    subprocess.run("pip install flask -y")
    """
    
    # Case 2: JS block comment containing input()
    code_js_comment = """
    /*
    input('This is a block comment bypass attempt')
    */
    const exec = require('child_process').exec;
    exec('npm install express -y');
    """
    
    # Case 3: log string containing input(
    code_string = """
    import subprocess
    print("Do not trigger input( here")
    subprocess.run("pip install flask -y")
    """

    auditor = SilentInstaller()
    
    f1 = tmp_path / "docstring.py"
    f1.write_text(code_docstring, encoding="utf-8")
    findings1 = auditor.scan([str(f1)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings1)

    f2 = tmp_path / "comment.sh"
    f2.write_text(code_js_comment, encoding="utf-8")
    findings2 = auditor.scan([str(f2)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings2)

    f3 = tmp_path / "logstr.py"
    f3.write_text(code_string, encoding="utf-8")
    findings3 = auditor.scan([str(f3)], None)
    assert any(f["name"] == "Silent Package Installation" for f in findings3)

