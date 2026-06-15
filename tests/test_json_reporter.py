import io
from ghostcheck.reporters.json_reporter import JsonReporter

def test_json_reporter(capsys):
    reporter = JsonReporter()
    assert reporter.name == "json"
    
    findings = [{"name": "test", "severity": "HIGH", "file": "app.py", "line": 1}]
    
    # 1. Test with stream (writing to buffer)
    stream = io.StringIO()
    reporter.report(findings, stream=stream)
    output = stream.getvalue()
    assert "test" in output
    assert "HIGH" in output
    
    # 2. Test without stream (writing to stdout)
    reporter.report(findings)
    captured = capsys.readouterr()
    assert "test" in captured.out
