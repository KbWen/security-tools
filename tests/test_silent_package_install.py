import pytest
from ghostcheck.checks.silent_package_install_detector import SilentPackageInstallDetector

def test_silent_package_install_detected(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "unsafe_tool.py"
    f.write_text("""
from langchain.agents import tool
import subprocess

@tool
def install_helper(package):
    # Runs pip install silently inside a tool
    subprocess.run(["pip", "install", "-y", package])
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Silent Package Installation" for fnd in findings)
    assert any(fnd["severity"] == "HIGH" for fnd in findings)

def test_unpinned_install_detected(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "unpinned_tool.py"
    f.write_text("""
from langchain.agents import tool
import os

@tool
def setup_package():
    # Installs unpinned package dynamically
    os.system("pip install requests")
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any("pinning" in fnd["message"] or "version" in fnd["message"] for fnd in findings)

def test_safe_setup_script(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "setup.py"
    f.write_text("""
# Regular setup script containing pip execution is fine since it is not a Tool file
import subprocess
subprocess.run(["pip", "install", "requests==2.28.1"])
""")
    
    findings = checker.scan([str(f)], config=None)
    assert not any(fnd["name"] == "Silent Package Installation" for fnd in findings)

def test_silent_package_install_concat_evasion(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "unsafe_concat_tool.py"
    f.write_text("""
from langchain.agents import tool
import subprocess

@tool
def install_helper(package):
    # Runs pip install silently inside a tool using string concatenation evasion
    cmd = "p" + "i" + "p" + " install " + "-y " + package
    subprocess.run(cmd, shell=True)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Silent Package Installation" for fnd in findings)

def test_silent_package_install_list_variable(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "unsafe_list_var_tool.py"
    f.write_text("""
from langchain.agents import tool
import subprocess

@tool
def install_helper(package):
    args = ["pip", "install", "-y", package]
    subprocess.run(args)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Silent Package Installation" for fnd in findings)

def test_silent_package_install_fstring(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "unsafe_fstring_tool.py"
    f.write_text("""
from langchain.agents import tool
import subprocess

@tool
def install_helper(package):
    cmd = f"pip install -y {package}"
    subprocess.run(cmd, shell=True)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Silent Package Installation" for fnd in findings)

def test_silent_package_install_mcp_decorator(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "generic_server.py"
    f.write_text("""
import mcp
import subprocess

@mcp.tool()
def install_helper(package):
    subprocess.run("pip install -y " + package, shell=True)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Silent Package Installation" for fnd in findings)

def test_silent_package_install_pip3(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "unsafe_pip3_tool.py"
    f.write_text("""
from langchain.agents import tool
import subprocess

@tool
def install_helper(package):
    subprocess.run("pip3 install -y " + package, shell=True)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Silent Package Installation" for fnd in findings)

def test_silent_package_install_subprocess_alias(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "unsafe_alias_tool.py"
    f.write_text("""
from langchain.agents import tool
import subprocess as sp

@tool
def install_helper(package):
    sp.run(["pip", "install", "-y", package])
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Silent Package Installation" for fnd in findings)

def test_silent_package_install_pinning_false_positives(tmp_path):
    checker = SilentPackageInstallDetector()
    f = tmp_path / "safe_pinning_tool.py"
    f.write_text("""
from langchain.agents import tool
import subprocess

@tool
def setup_dev_env():
    subprocess.run("pip install -r requirements-dev.txt", shell=True)
    subprocess.run("pip install -e .", shell=True)
""")
    findings = checker.scan([str(f)], config=None)
    unpinned_findings = [fnd for fnd in findings if "version is not pinned" in fnd["message"]]
    assert len(unpinned_findings) == 0

