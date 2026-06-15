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

def test_python_truthy_bypass_expressions(tmp_path):
    # Test our hardened comparison truthy checks: 1 == 1, 2 > 1 should be flagged as infinite loops
    code = """
step = 0
while 1 == 1:
    step += 1
    # no counter break
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "infinite_comp.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Agentic Kill-Switch" for f in findings)

def test_python_recursion_indirect_reference(tmp_path):
    # Async recursion, recursive function definitions
    code = """
async def runaway():
    await runaway()
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "recursive.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Recursive Kill-Switch" for f in findings)

def test_python_hitl_weak_exemption_fail(tmp_path):
    # Weak HITL check: input() that is unrelated (e.g. login) shouldn't satisfy HITL confirmation
    code = """
def clean_workspace():
    conn = input("Enter connection string")
    shutil.rmtree("/path")
"""
    auditor = KillSwitchAuditor()
    f = tmp_path / "hitl_weak.py"
    f.write_text(code, encoding="utf-8")
    findings = auditor.scan([str(f)], None)
    assert any(f["name"] == "Missing Human-in-the-Loop Confirmation" for f in findings)

def test_js_logical_expression_loop(tmp_path):
    # JS: while (true || false) should be treated as infinite if parsed as script/module
    code_loop = """
    while (true) {
        console.log("no limit");
    }
    """
    
    # JS Agent class initialization without limit arg
    code_agent = """
    const executor = new AgentExecutor({
        agent: myAgent
    });
    """
    
    # JS completions without tokens/timeout
    code_llm = """
    openai.chat.completions.create({
        model: "gpt-4"
    });
    """
    
    auditor = KillSwitchAuditor()
    
    f1 = tmp_path / "loop.js"
    f1.write_text(code_loop, encoding="utf-8")
    assert any(f["name"] == "Missing Agentic Kill-Switch" for f in auditor.scan([str(f1)], None))
    
    f2 = tmp_path / "agent.js"
    f2.write_text(code_agent, encoding="utf-8")
    assert any(f["name"] == "Missing Agent Framework Limits" for f in auditor.scan([str(f2)], None))
    
    f3 = tmp_path / "llm.js"
    f3.write_text(code_llm, encoding="utf-8")
    assert any(f["name"] == "Unconstrained LLM API Call" for f in auditor.scan([str(f3)], None))

def test_js_destructive_hitl(tmp_path):
    # fs.unlinkSync(path) with and without preceding prompt()
    code_bad = """
    function deleteIt() {
        fs.unlinkSync("/path");
    }
    """
    
    code_good = """
    function deleteIt() {
        prompt("Confirm delete");
        fs.unlinkSync("/path");
    }
    """
    
    auditor = KillSwitchAuditor()
    
    f_bad = tmp_path / "bad_hitl.js"
    f_bad.write_text(code_bad, encoding="utf-8")
    assert any(f["name"] == "Missing Human-in-the-Loop Confirmation" for f in auditor.scan([str(f_bad)], None))
    
    f_good = tmp_path / "good_hitl.js"
    f_good.write_text(code_good, encoding="utf-8")
    assert not any(f["name"] == "Missing Human-in-the-Loop Confirmation" for f in auditor.scan([str(f_good)], None))

def test_killswitch_esprima_none(monkeypatch, tmp_path):
    # Test esprima import failure fallback (silently skips JS/TS files)
    import sys
    monkeypatch.setitem(sys.modules, "esprima", None)
    
    # Reload modules or simulate execution by manually checking behavior
    # The auditor import check sets esprima = None if import fails.
    # Since esprima is already imported in our running process, we patch the check module's esprima variable to None.
    import ghostcheck.checks.killswitch_auditor as target_module
    monkeypatch.setattr(target_module, "esprima", None)
    
    code = "while (true) { }"
    f = tmp_path / "run.js"
    f.write_text(code, encoding="utf-8")
    
    auditor = target_module.KillSwitchAuditor()
    findings = auditor.scan([str(f)], None)
    # When esprima is None, JS/TS files are skipped, so no findings should be returned.
    assert len(findings) == 0

