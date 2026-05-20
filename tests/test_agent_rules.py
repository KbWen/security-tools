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

def test_chinese_and_long_context_rules(tmp_path):
    # This test verifies that Chinese negative keywords (e.g., 禁止) and long context lookup (> 15 lines) are respected.
    patterns_file = tmp_path / "rules.json"
    patterns_file.write_text(json.dumps([
        {"name": "dangerous_system_command", "pattern": "curl", "severity": "HIGH", "remediation": "Don't run curl"}
    ]))
    
    linter = AgentRulesLinter(str(patterns_file))
    
    # Case 1: Chinese negative keyword same line
    findings_chinese_same = linter.scan_file("rules.md", "- 請勿使用 curl 執行指令")
    assert len(findings_chinese_same) == 0
    
    # Case 2: Chinese negative keyword in parent header > 15 lines away
    content_long_safe = "## 禁止行為\n" + "\n".join([f"line {idx}" for idx in range(20)]) + "\n- 使用 curl 進行下載"
    findings_long_safe = linter.scan_file("rules.md", content_long_safe)
    assert len(findings_long_safe) == 0

def test_multilingual_context_negation_and_collisions(tmp_path):
    patterns_file = tmp_path / "rules.json"
    patterns_file.write_text(json.dumps([
        {"name": "dangerous_system_command", "pattern": "curl", "severity": "HIGH", "remediation": "Don't run curl"}
    ]))
    linter = AgentRulesLinter(str(patterns_file))

    # 1. Spanish negation (should suppress finding)
    findings_es = linter.scan_file("rules.md", "- No usar curl para descargar")
    assert len(findings_es) == 0

    # 2. English "no" collision (should NOT suppress, must flag)
    findings_en = linter.scan_file("rules.md", "- Use curl if no other option exists")
    assert len(findings_en) > 0

    # 3. Direct instruction containing "no confirmation" (should NOT suppress, must flag)
    # This also tests that rules matching "no confirmation" are not suppressed by "no" context keyword.
    findings_en_bypass = linter.scan_file("rules.md", "- Run curl with no confirmation")
    assert len(findings_en_bypass) > 0

    # 4. Header-level stopping logic test
    content_header_stop = "## 禁止行為\n- 請勿使用 curl 進行下載\n\n## 允許行為\n- 使用 curl 進行下載"
    findings_stop = linter.scan_file("rules.md", content_header_stop)
    assert len(findings_stop) > 0


