import pytest
from ghostcheck.reporters.owasp_llm_reporter import OWASPLLMReporter
import io

def test_owasp_reporter_grouping():
    reporter = OWASPLLMReporter(use_color=False)
    findings = [
        {
            "name": "Hidden Prompt Injection",
            "file": "AGENTS.md",
            "line": 10,
            "severity": "CRITICAL",
            "owasp_llm": "LLM01: Prompt Injection"
        },
        {
            "name": "Hardcoded AWS Key",
            "file": "src/main.py",
            "line": 5,
            "severity": "HIGH",
            "owasp_llm": "LLM02: Sensitive Information Disclosure"
        },
        {
            "name": "Unmapped Issue",
            "file": "README.md",
            "severity": "LOW"
        }
    ]
    
    stream = io.StringIO()
    reporter.report(findings, stream=stream)
    output = stream.getvalue()
    
    # Check for categories
    assert "LLM01: Prompt Injection" in output
    assert "LLM02: Sensitive Information Disclosure" in output
    assert "Other Security Findings" in output
    assert "Compliance Ratio" in output
    # Check for grouping (2/5 categories should pass based on categories defined in reporter)
    # Actually categories in reporter are 5, we hit 2, so 3 should pass? 
    # Wait, categories are: LLM01, LLM02, LLM03, LLM06, LLM09.
    # We hit LLM01 and LLM02. So LLM03, LLM06, LLM09 remain PASSED.
    # 所以 pass 3/5 = 60%.
    assert "60.0%" in output

def test_owasp_reporter_empty():
    reporter = OWASPLLMReporter(use_color=False)
    findings = []
    
    stream = io.StringIO()
    reporter.report(findings, stream=stream)
    output = stream.getvalue()
    
    assert "100.0%" in output
    assert "No violations detected" in output
