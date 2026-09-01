import json
import pytest
from ghostcheck.reporters.sarif_reporter import SarifReporter

def test_sarif_reporter(tmp_path):
    reporter = SarifReporter()
    findings = [
        {
            "file": "test.py",
            "line": 5,
            "name": "Hardcoded Secret",
            "severity": "HIGH",
            "message": "Found a hardcoded secret."
        },
        {
            "file": "src\\components\\auth.py",
            "line": 10,
            "pattern_name": "AWS Access Key",
            "severity": "CRITICAL",
            "suggestion": "Revoke immediately."
        }
    ]
    
    output_path = tmp_path / "report.sarif"
    reporter.report(findings, output_path=str(output_path))
    
    assert output_path.exists()
    
    with open(output_path, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
        
    assert sarif_data['version'] == "2.1.0"
    assert len(sarif_data['runs']) == 1
    run = sarif_data['runs'][0]
    
    rules = run['tool']['driver']['rules']
    assert len(rules) == 2
    rule_ids = [r['id'] for r in rules]
    assert "Hardcoded Secret" in rule_ids
    assert "AWS Access Key" in rule_ids
    
    results = run['results']
    assert len(results) == 2
    
    # Check mapping & URI normalization
    high_result = next(r for r in results if r['ruleId'] == "Hardcoded Secret")
    assert high_result['level'] == "error"
    assert high_result['message']['text'] == "Found a hardcoded secret."
    assert high_result['locations'][0]['physicalLocation']['artifactLocation']['uri'] == "test.py"
    
    critical_result = next(r for r in results if r['ruleId'] == "AWS Access Key")
    assert critical_result['level'] == "error"
    assert critical_result['message']['text'] == "Revoke immediately."
    # Backslashes normalized to forward slashes for SARIF 2.1.0 standard
    assert critical_result['locations'][0]['physicalLocation']['artifactLocation']['uri'] == "src/components/auth.py"

