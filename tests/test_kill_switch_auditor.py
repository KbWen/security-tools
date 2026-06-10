import pytest
from ghostcheck.checks.kill_switch_auditor import KillSwitchAuditor

def test_missing_kill_switch_loop(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "unsafe_loop.py"
    f.write_text("""
def run_loop():
    # Infinite loop without count limiter
    while True:
        do_something()
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Missing Agentic Kill-Switch" for fnd in findings)
    assert any(fnd["severity"] == "HIGH" for fnd in findings)

def test_safe_kill_switch_loop(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "safe_loop.py"
    f.write_text("""
def run_loop():
    steps = 0
    while True:
        do_something()
        steps += 1
        # Safe count limit break
        if steps > 10:
            break
""")
    
    findings = checker.scan([str(f)], config=None)
    assert not any(fnd["name"] == "Missing Agentic Kill-Switch" for fnd in findings)

def test_agent_framework_limits(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "agent_limits.py"
    f.write_text("""
# Missing limit params
agent = AgentExecutor(agent=agent, tools=tools)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Missing Agent Framework Limits" for fnd in findings)

def test_unconstrained_llm_call(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "llm_limits.py"
    f.write_text("""
# Completion call lacking max_tokens or timeout
response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "hello"}]
)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Unconstrained LLM API Call" for fnd in findings)

def test_missing_hitl(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "unsafe_delete.py"
    f.write_text("""
import shutil

# Destructive action without input() prompt
def delete_workspace():
    shutil.rmtree("/tmp/workspace")
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Missing Human-in-the-Loop Confirmation" for fnd in findings)
    assert any(fnd["severity"] == "HIGH" for fnd in findings)

def test_safe_hitl(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "safe_delete.py"
    f.write_text("""
import shutil

# Destructive action with preceding confirmation
def delete_workspace():
    confirm = input("Are you sure? ")
    if confirm.lower() == 'yes':
        shutil.rmtree("/tmp/workspace")
""")
    
    findings = checker.scan([str(f)], config=None)
    assert not any(fnd["name"] == "Missing Human-in-the-Loop Confirmation" for fnd in findings)

def test_kill_switch_bypass_truthy_loops(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "truthy_loops.py"
    f.write_text("""
def run_loop_1():
    while 1:
        do_something()

def run_loop_2():
    while not False:
        do_something()

def run_loop_3():
    while -1:
        do_something()
""")
    findings = checker.scan([str(f)], config=None)
    assert len([fnd for fnd in findings if fnd["name"] == "Missing Agentic Kill-Switch"]) == 3

def test_kill_switch_integer_compare_limit(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "compare_limits.py"
    f.write_text("""
def run_loop_1():
    i = 0
    while i < 10:
        do_something()
        i += 1

def run_loop_2():
    while True:
        do_something()
        if i > 10:
            break
""")
    findings = checker.scan([str(f)], config=None)
    assert not any(fnd["name"] == "Missing Agentic Kill-Switch" for fnd in findings)

def test_kill_switch_runaway_recursion(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "recursion_limits.py"
    f.write_text("""
def runaway_recurse():
    runaway_recurse()

def safe_recurse(depth=0):
    if depth > 10:
        return
    safe_recurse(depth + 1)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Missing Recursive Kill-Switch" for fnd in findings)
    assert len([fnd for fnd in findings if fnd["name"] == "Missing Recursive Kill-Switch"]) == 1

def test_kill_switch_hitl_ordering(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "hitl_order.py"
    f.write_text("""
import shutil
def delete_workspace():
    shutil.rmtree("/tmp/workspace")
    confirm = input("Are you sure? ")
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Missing Human-in-the-Loop Confirmation" for fnd in findings)

def test_kill_switch_fqcn_agent_framework(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "fqcn_agent.py"
    f.write_text("""
from langchain.agents import AgentExecutor
agent = AgentExecutor(agent=agent, tools=tools)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Missing Agent Framework Limits" for fnd in findings)

def test_kill_switch_float_limit_check(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "float_limit.py"
    f.write_text("""
def run_loop():
    steps = 0.0
    while True:
        do_something()
        steps += 1.0
        if steps > 10.0:
            break
""")
    findings = checker.scan([str(f)], config=None)
    assert not any(fnd["name"] == "Missing Agentic Kill-Switch" for fnd in findings)

def test_kill_switch_hitl_unrelated_bypass(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "hitl_unrelated.py"
    f.write_text("""
import shutil
def delete_workspace():
    confirm_login()
    shutil.rmtree("/tmp/workspace")
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Missing Human-in-the-Loop Confirmation" for fnd in findings)

def test_kill_switch_llm_extended_methods(tmp_path):
    checker = KillSwitchAuditor()
    f = tmp_path / "llm_extended.py"
    f.write_text("""
response = client.messages.create(
    model="claude-3",
    messages=[{"role": "user", "content": "hello"}]
)
""")
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "Unconstrained LLM API Call" for fnd in findings)
