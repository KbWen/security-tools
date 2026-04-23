import pytest
import os
from ghostcheck.checks.context_auditor import ContextAuditor
from ghostcheck.scanner import Scanner

def test_context_auditor_basic():
    auditor = ContextAuditor()
    
    # Not a doc file
    assert not auditor.is_safe_context("script.py", "never do this", 1)
    
    # Same line context
    assert auditor.is_safe_context("docs.md", "Rule 1: Never leave AWS_ACCESS_KEY_ID in code.", 1)
    assert auditor.is_safe_context("AGENTS.md", "Example: AKIAIOSFODNN7EXAMPLE", 1)
    
    # Block context
    content = """
    We strictly prohibit the following:
    - Running rm -rf /
    - Leaving AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in code
    """
    # The negative keyword "prohibit" is in the text.
    assert auditor.is_safe_context("rules.md", content, 4) # rm -rf line
    assert auditor.is_safe_context("rules.md", content, 5) # AWS key line

def test_scanner_integration_suppression(tmp_path):
    # Create a dummy rule file
    doc_path = tmp_path / "AGENTS.md"
    doc_path.write_text("Never commit tokens like AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE.")
    
    # Scanner without context intelligence would flag this.
    # With context intelligence, it should be suppressed.
    scanner = Scanner(str(tmp_path), offline=True)
    findings = scanner.scan()
    
    # The secret should be suppressed
    assert len([f for f in findings if f.get('name') == 'AWS Access Key' or f.get('pattern_name') == 'AWS Access Key']) == 0

def test_scanner_integration_active_secret(tmp_path):
    # Create a python file with an active secret
    code_path = tmp_path / "script.py"
    code_path.write_text('token = "AKIAIOSFODNN7EXAMPLE"')
    
    scanner = Scanner(str(tmp_path), offline=True)
    findings = scanner.scan()
    
    # The secret should be flagged
    assert len([f for f in findings if f.get('name') == 'AWS Access Key' or f.get('pattern_name') == 'AWS Access Key']) == 1

def test_entropy_scanner_markdown(tmp_path):
    doc_path = tmp_path / "README.md"
    # A base64-like string that is high entropy but common in docs
    doc_path.write_text("Here is a token: aGVsbG9fd29ybGRfdGhpc19pc19hX3Rlc3RfdG9rZW4K")
    
    code_path = tmp_path / "config.env"
    code_path.write_text("SECRET=aGVsbG9fd29ybGRfdGhpc19pc19hX3Rlc3RfdG9rZW4K")
    
    scanner = Scanner(str(tmp_path), offline=True)
    findings = scanner.scan()
    
    # The markdown one should be suppressed due to higher threshold.
    # The env one should be flagged.
    doc_findings = [f for f in findings if f['file'].endswith('README.md') and (f.get('name') == 'high_entropy_secret' or f.get('rule_name') == 'high_entropy_secret')]
    env_findings = [f for f in findings if f['file'].endswith('config.env') and (f.get('name') == 'high_entropy_secret' or f.get('rule_name') == 'high_entropy_secret')]
    
    assert len(doc_findings) == 0
    assert len(env_findings) == 1
