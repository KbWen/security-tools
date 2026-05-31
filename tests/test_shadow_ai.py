import pytest
from ghostcheck.checks.shadow_ai import ShadowAIDetector

def test_python_ai_imports():
    detector = ShadowAIDetector()
    
    # Positive case: unauthorized imports
    content = "import openai\nfrom anthropic import Anthropic\nimport langchain"
    findings = detector.scan_file("src/agent.py", content)
    
    rule_ids = {f["rule_id"] for f in findings}
    assert "GSA-01" in rule_ids
    assert len(findings) == 3
    
    # Negative case: non-AI imports
    content_safe = "import os\nimport requests\nfrom collections import defaultdict"
    findings_safe = detector.scan_file("src/agent.py", content_safe)
    assert len(findings_safe) == 0

def test_js_ai_imports():
    detector = ShadowAIDetector()
    
    # Positive cases
    content_req = "const openai = require('openai');\nconst langchain = require('langchain');"
    findings_req = detector.scan_file("web/index.js", content_req)
    assert len(findings_req) == 2
    assert findings_req[0]["rule_id"] == "GSA-02"
    
    content_import = "import { Anthropic } from '@anthropic-ai/sdk';\nimport { ChatOpenAI } from '@langchain/core';"
    findings_import = detector.scan_file("web/app.ts", content_import)
    assert len(findings_import) == 2
    assert all(f["rule_id"] == "GSA-02" for f in findings_import)

def test_manifest_dependencies():
    detector = ShadowAIDetector()
    
    # requirements.txt
    req_content = "openai>=1.0.0\nrequests==2.31.0\nlangchain\n# this is a comment"
    findings_req = detector.scan_file("requirements.txt", req_content)
    assert len(findings_req) == 2
    assert all(f["rule_id"] == "GSA-03" for f in findings_req)
    
    # package.json
    pkg_content = """{
        "dependencies": {
            "express": "^4.18.2",
            "openai": "^4.20.0"
        },
        "devDependencies": {
            "typescript": "^5.0.0",
            "@google/generative-ai": "^0.1.0"
        }
    }"""
    findings_pkg = detector.scan_file("package.json", pkg_content)
    assert len(findings_pkg) == 2
    assert all(f["rule_id"] == "GSA-03" for f in findings_pkg)

def test_pyproject_toml_dependencies():
    detector = ShadowAIDetector()
    
    toml_content = """
    [tool.poetry.dependencies]
    python = "^3.10"
    openai = "^1.2.0"
    requests = "^2.28.0"
    dependencies = [
        "langchain>=0.1.0",
        "urllib3"
    ]
    """
    findings = detector.scan_file("pyproject.toml", toml_content)
    assert len(findings) == 2
    assert all(f["rule_id"] == "GSA-03" for f in findings)

def test_local_llm_endpoints():
    detector = ShadowAIDetector()
    
    content = """
    # Ollama endpoint
    OLLAMA_API = "http://localhost:11434/v1"
    # Llama.cpp endpoint
    LLAMA_API = "http://127.0.0.1:8080/v1"
    # vLLM endpoint
    VLLM_API = "http://localhost:8000/v1"
    # Safe endpoint
    APPROVED_API = "https://api.approved-corp-ai.com/v1"
    """
    findings = detector.scan_file("src/config.py", content)
    assert len(findings) == 3
    assert all(f["rule_id"] == "GSA-04" for f in findings)

def test_local_llm_env_vars():
    detector = ShadowAIDetector()
    
    content = """
    OLLAMA_HOST=0.0.0.0
    LOCAL_LLM_URL=http://localhost:11434
    """
    findings = detector.scan_file(".env", content)
    # 2 env vars (OLLAMA_HOST, LOCAL_LLM_URL) + 1 endpoint URL in LOCAL_LLM_URL = 3 findings total
    rule_ids = [f["rule_id"] for f in findings]
    assert rule_ids.count("GSA-05") == 2
    assert "GSA-04" in rule_ids

def test_vscode_extensions():
    detector = ShadowAIDetector()
    
    ext_content = """{
        "recommendations": [
            "dbaeumer.vscode-eslint",
            "github.copilot",
            "codeium.codeium"
        ]
    }"""
    findings = detector.scan_file(".vscode/extensions.json", ext_content)
    assert len(findings) == 2
    assert all(f["rule_id"] == "GSA-06" for f in findings)

def test_custom_config_filtering():
    # Allow google-generativeai and block openai explicitly
    config = {
        "shadow_ai": {
            "allowed_sdks": ["google.generativeai", "@google/generative-ai"],
            "blocked_sdks": ["openai"],
            "allowed_endpoints": ["http://localhost:11434/v1"]
        }
    }
    detector = ShadowAIDetector(config=config)
    
    # google.generativeai should not flag since it's allowed
    content = "import google.generativeai\nimport openai\nimport anthropic"
    findings = detector.scan_file("src/agent.py", content)
    # openai: flagged (explicitly blocked)
    # anthropic: not flagged (blocked_sdks is non-empty, so it only flags blocked_sdks list)
    assert len(findings) == 1
    assert findings[0]["message"] == "Unauthorized Python AI SDK imported: 'openai'."

    # Test allowed local endpoint
    content_url = "BASE_URL = 'http://localhost:11434/v1'"
    findings_url = detector.scan_file("src/config.py", content_url)
    assert len(findings_url) == 0

def test_shadow_ai_malformed_manifests():
    detector = ShadowAIDetector()

    # Malformed package.json
    malformed_pkg = """{
        "dependencies": {
            "openai": "^4.20.0",
    """  # invalid JSON
    findings = detector.scan_file("package.json", malformed_pkg)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "GSA-03"
    assert "fallback" in findings[0]["message"]

    # Malformed extensions.json
    malformed_ext = """{
        "recommendations": [
            "github.copilot"
    """  # invalid JSON
    findings_ext = detector.scan_file(".vscode/extensions.json", malformed_ext)
    assert len(findings_ext) == 1
    assert findings_ext[0]["rule_id"] == "GSA-06"
    assert "fallback" in findings_ext[0]["message"]

def test_shadow_ai_js_namespaces():
    detector = ShadowAIDetector()
    
    # Test namespace prefix matching
    content = "import { Chat } from '@langchain/openai';"
    findings = detector.scan_file("src/index.js", content)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "GSA-02"

def test_shadow_ai_non_matching_files():
    detector = ShadowAIDetector()
    
    # Text file that isn't a manifest should not run manifest scans
    content = "openai>=1.0.0"
    findings = detector.scan_file("README.md", content)
    assert len(findings) == 0

def test_shadow_ai_empty_config():
    # Explicitly test with None and empty dict config parameter
    d1 = ShadowAIDetector(config=None)
    d2 = ShadowAIDetector(config={})
    
    content = "import openai"
    assert len(d1.scan_file("src/agent.py", content)) == 1
    assert len(d2.scan_file("src/agent.py", content)) == 1

def test_shadow_ai_comment_ignoring():
    detector = ShadowAIDetector()
    
    # Python code comments
    py_content = """
    # import openai
    import os  # We do not use langchain here
    import anthropic
    """
    py_findings = detector.scan_file("src/agent.py", py_content)
    # import anthropic: flags (1 finding)
    # import openai and langchain are inside comments, should be skipped
    assert len(py_findings) == 1
    assert py_findings[0]["name"] == "unauthorized_ai_sdk_python"
    
    # JS/TS code comments
    js_content = """
    // const openai = require('openai');
    /* 
      import { Anthropic } from '@anthropic-ai/sdk';
    */
    const langchain = require('langchain'); // Flagged
    """
    js_findings = detector.scan_file("web/app.js", js_content)
    # langchain: flagged (1 finding)
    # openai and Anthropic are inside comments, should be skipped
    assert len(js_findings) == 1
    assert js_findings[0]["name"] == "unauthorized_ai_sdk_js"

