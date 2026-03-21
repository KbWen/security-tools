from ghostcheck.checks.severity_engine import SeverityEngine

def test_severity_downgrade():
    engine = SeverityEngine("/root")
    finding = {"file": "tests/data.py", "severity": "HIGH", "value_preview": "sk-1234567890"}
    
    # Path based downgrade
    engine.adjust_finding(finding)
    assert finding["severity"] == "MEDIUM"
    assert "test" in finding["adjustment_reason"]

def test_severity_entropy():
    engine = SeverityEngine("/root")
    # Low entropy string
    finding = {"file": "src/main.py", "severity": "HIGH", "value_preview": "aaaaaaaaaaaa"}
    engine.adjust_finding(finding)
    assert finding["severity"] == "MEDIUM"
    assert "low entropy" in finding["adjustment_reason"]
