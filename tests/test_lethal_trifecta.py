import pytest
from ghostcheck.checks.lethal_trifecta_detector import LethalTrifectaDetector

def test_lethal_trifecta_detected(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_unsafe.py"
    f.write_text("""
import os
import subprocess

# Defines a tool scope containing the lethal trifecta
def execute_agent_tool(user_query):
    # 1. Untrusted Input: parameter user_query
    # 2. Private Data Access: open()
    with open("config.txt", "r") as cfg:
        conf = cfg.read()
    
    # 3. Tool Execution: subprocess.run()
    subprocess.run("echo " + user_query, shell=True)
""")
    
    findings = checker.scan([str(f)], config=None)
    # The function execute_agent_tool scope contains all 3 capabilities
    assert any(fnd["name"] == "Lethal Trifecta Detected" for fnd in findings)
    assert any(fnd["severity"] == "CRITICAL" for fnd in findings)

def test_elevated_privilege(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_elevated.py"
    f.write_text("""
import os
import subprocess

def execute_safe_tool(user_query):
    # Only 2 capabilities: Untrusted Input and Tool Execution (no Private Data Access)
    subprocess.run("echo " + user_query, shell=True)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Elevated Agent Privilege" for fnd in findings)
    assert any(fnd["severity"] == "WARNING" for fnd in findings)

def test_capability_registered(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_info.py"
    f.write_text("""
import os

def read_only_action():
    # Only 1 capability: Private Data Access (open)
    with open("data.json") as data:
        return data.read()
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Agent Capability Registered" for fnd in findings)
    assert any(fnd["severity"] == "INFO" for fnd in findings)

def test_lethal_trifecta_with_aliases(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_aliased.py"
    f.write_text("""
from subprocess import run as r
import os as operating_system

def execute_agent_tool(user_query):
    # 1. Untrusted Input: user_query
    # 2. Private Data Access: operating_system.getenv
    key = operating_system.getenv("API_KEY")
    # 3. Tool Execution: r() (alias for subprocess.run)
    r("echo " + user_query, shell=True)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Lethal Trifecta Detected" for fnd in findings)
    assert any(fnd["severity"] == "CRITICAL" for fnd in findings)

def test_lethal_trifecta_bypass_alternative_exec(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_posix_exec.py"
    f.write_text("""
import posix
def execute_agent_tool(user_query):
    with open("config.txt", "r") as cfg:
        conf = cfg.read()
    posix.system("echo " + user_query)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Lethal Trifecta Detected" for fnd in findings)

def test_lethal_trifecta_bypass_custom_file_apis(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_pathlib.py"
    f.write_text("""
from pathlib import Path
import subprocess
def execute_agent_tool(user_query):
    conf = Path("config.txt").read_text()
    subprocess.run("echo " + user_query, shell=True)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Lethal Trifecta Detected" for fnd in findings)

def test_lethal_trifecta_bypass_environ_import(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_environ_import.py"
    f.write_text("""
from os import environ
import subprocess
def execute_agent_tool(user_query):
    key = environ["API_KEY"]
    subprocess.run("echo " + user_query, shell=True)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Lethal Trifecta Detected" for fnd in findings)

def test_lethal_trifecta_bypass_mcp_decorators_and_request(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_mcp.py"
    f.write_text("""
import mcp
import subprocess
from pathlib import Path

@mcp.tool()
async def execute_agent_tool(r: Request):
    key = Path("config.txt").read_text()
    subprocess.run("echo " + r.query, shell=True)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Lethal Trifecta Detected" for fnd in findings)

def test_lethal_trifecta_deduplication(tmp_path):
    checker = LethalTrifectaDetector()
    f = tmp_path / "agent_nested.py"
    f.write_text("""
import subprocess
def outer_function(user_query):
    def inner_function():
        with open("config.txt") as f:
            data = f.read()
        subprocess.run("echo " + user_query, shell=True)
    inner_function()
""")
    findings = checker.scan([str(f)], config=None)
    trifectas = [fnd for fnd in findings if fnd["name"] == "Lethal Trifecta Detected"]
    assert len(trifectas) == 1

