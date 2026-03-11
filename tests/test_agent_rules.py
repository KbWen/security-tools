import json
from ghostcheck.checks.agent_rules import AgentRulesLinter

def test_rules_lint(tmp_path):
    patterns_file = tmp_path / "rules.json"
    patterns_file.write_text(json.dumps([
        {"name": "Dangerous", "pattern": "rm -rf", "severity": "CRITICAL", "remediation": "Don't"}
    ]))
    
    linter = AgentRulesLinter(str(patterns_file))
    content = "Rule 1: Never use rm -rf on the host."
    findings = linter.scan_file("rules.md", content)
    
    assert len(findings) == 1
    assert findings[0]['rule_name'] == "Dangerous"
    assert findings[0]['severity'] == "CRITICAL"
