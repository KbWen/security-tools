import pytest
from ghostcheck.checks.killswitch_auditor import KillSwitchAuditor

def test_python_infinite_loop_compliant(tmp_path):
    # Compliant: contains limit breaks
    code = """
step = 0
while True:
    step += 1
    if step > 10:
        break
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert not any(f["name"] == "Missing Agentic Kill-Switch" for f in findings)

def test_python_infinite_loop_non_compliant(tmp_path):
    # Non-compliant: lacks step cap
    code = """
while True:
    print("running forever")
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Agentic Kill-Switch" for f in findings)

def test_python_recursive_compliant(tmp_path):
    code = """
def run(depth):
    if depth > 10:
        return
    run(depth + 1)
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert not any(f["name"] == "Missing Recursive Kill-Switch" for f in findings)

def test_python_recursive_non_compliant(tmp_path):
    code = """
def run():
    run()
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Recursive Kill-Switch" for f in findings)

def test_python_llm_limits(tmp_path):
    # missing constraints
    code = """
import openai
openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "hi"}]
)
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Unconstrained LLM API Call" for f in findings)

def test_python_hitl_compliant(tmp_path):
    # Destructive operation preceded by input()
    code = """
def clean_workspace():
    confirm = input("Are you sure you want to delete?")
    if "yes" in confirm.lower():
        shutil.rmtree("/path")
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert not any(f["name"] == "Missing Human-in-the-Loop Confirmation" for f in findings)

def test_python_hitl_non_compliant(tmp_path):
    # Destructive operation missing input()
    code = """
def clean_workspace():
    shutil.rmtree("/path")
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Human-in-the-Loop Confirmation" for f in findings)

def test_js_infinite_loop_compliant(tmp_path):
    code = """
let step = 0;
while (true) {
    step++;
    if (step > 10) {
        break;
    }
}
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.js"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert not any(f["name"] == "Missing Agentic Kill-Switch" for f in findings)

def test_js_infinite_loop_non_compliant(tmp_path):
    code = """
while (true) {
    console.log("forever");
}
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.js"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Agentic Kill-Switch" for f in findings)

def test_js_infinite_loop_return_compliant(tmp_path):
    code = """
function run() {
    let step = 0;
    while (true) {
        step++;
        if (step > 10) {
            return;
        }
    }
}
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "test_loop.js"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert not any(f["name"] == "Missing Agentic Kill-Switch" for f in findings)
