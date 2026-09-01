import os
import pytest
from ghostcheck.checks.shadow_ai import ShadowAIDetector
from ghostcheck.ignorefile import IgnoreMatcher
from ghostcheck.checks.ci_auditor import CIAuditor

def test_shadow_ai_python_ast_constant_folding():
    detector = ShadowAIDetector()
    
    # 1. Simple binary addition
    code_binop = "__import__('open' + 'ai')\n"
    findings = detector.scan_file("test_script.py", code_binop)
    assert any(f.get("name") == "unauthorized_ai_sdk_python" for f in findings)

    # 2. Nested binary addition
    code_nested = "import importlib\nimportlib.import_module('an' + 'thro' + 'pic')\n"
    findings_nested = detector.scan_file("test_nested.py", code_nested)
    assert any(f.get("name") == "unauthorized_ai_sdk_python" for f in findings_nested)

    # 3. Standard direct import
    code_direct = "import openai\n"
    findings_direct = detector.scan_file("test_direct.py", code_direct)
    assert any(f.get("name") == "unauthorized_ai_sdk_python" for f in findings_direct)

def test_shadow_ai_js_concatenation_folding():
    detector = ShadowAIDetector()
    
    # 1. String concatenation inside require
    code_js_concat = "const ai = require('open' + 'ai');\n"
    findings = detector.scan_file("test_app.js", code_js_concat)
    assert any(f.get("name") == "unauthorized_ai_sdk_js" for f in findings)

    # 2. String concatenation with double quotes
    code_js_double = 'const lc = require("lang" + "chain");\n'
    findings_double = detector.scan_file("test_app2.js", code_js_double)
    assert any(f.get("name") == "unauthorized_ai_sdk_js" for f in findings_double)

def test_ignore_matcher_dot_directory_preservation():
    matcher = IgnoreMatcher(base_path=".")
    
    # Check that .git, .venv, .pytest_cache and their subpaths are correctly ignored
    assert matcher.is_ignored(".git/worktrees/subagent-1/gitdir") is True
    assert matcher.is_ignored(".git/config") is True
    assert matcher.is_ignored(".venv/lib/site-packages/pkg.py") is True
    assert matcher.is_ignored(".pytest_cache/v/cache/stepwise") is True
    assert matcher.is_ignored("dist/bundle.js") is True

    # Check that regular project source files are NOT ignored
    assert matcher.is_ignored("src/ghostcheck/cli.py") is False
    assert matcher.is_ignored("README.md") is False

def test_ci_auditor_pinned_actions():
    auditor = CIAuditor()
    
    # Pinned with 40-character SHA should NOT trigger gha_unpinned_action
    pinned_workflow = """
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38
"""
    findings_pinned = auditor.scan_file(".github/workflows/ci.yml", pinned_workflow)
    assert not any(f.get("name") == "gha_unpinned_action" for f in findings_pinned)

    # Unpinned tag reference SHOULD trigger gha_unpinned_action
    unpinned_workflow = """
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    findings_unpinned = auditor.scan_file(".github/workflows/ci.yml", unpinned_workflow)
    assert any(f.get("name") == "gha_unpinned_action" for f in findings_unpinned)
