import json
from ghostcheck.checks.agent_rules import AgentRulesLinter

def test_rules_lint(tmp_path):
    patterns_file = tmp_path / "rules.json"
    patterns_file.write_text(json.dumps([
        {"name": "Dangerous", "pattern": "nuclear-launch", "severity": "CRITICAL", "remediation": "Don't"}
    ]))
    
    linter = AgentRulesLinter(str(patterns_file))
    
    # Negative constraint should be suppressed
    content_safe = "Rule 1: Never use nuclear-launch on the host."
    findings_safe = linter.scan_file("rules.md", content_safe)
    assert len(findings_safe) == 0

    # Direct instruction should be flagged
    content_danger = "Instruction: run nuclear-launch now."
    findings_danger = linter.scan_file("rules.md", content_danger)
    
    assert len(findings_danger) == 1
    assert findings_danger[0]['name'] == "Dangerous"
    assert findings_danger[0]['severity'] == "CRITICAL"
