import pytest
from ghostcheck.checks.privilege_auditor import PrivilegeAuditor

def test_github_token_missing_permissions():
    """Verify that a workflow file missing a permissions block is flagged (GPA-01)."""
    auditor = PrivilegeAuditor()
    content = """
name: CI Workflow
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
    """
    findings = auditor.scan_file(".github/workflows/ci.yml", content)
    finding_names = [f['name'] for f in findings]
    assert "github_token_missing_permissions" in finding_names
    assert not any(f['name'] == "github_token_excessive_write" for f in findings)
    assert not any(f['name'] == "github_pr_target_write" for f in findings)

def test_github_token_excessive_write():
    """Verify that a workflow file with write scope is flagged (GPA-02)."""
    auditor = PrivilegeAuditor()
    content = """
name: CI Workflow
on: [push]
permissions:
  contents: write
  actions: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
    """
    findings = auditor.scan_file(".github/workflows/ci.yml", content)
    finding_names = [f['name'] for f in findings]
    assert "github_token_excessive_write" in finding_names
    assert "github_token_missing_permissions" not in finding_names

def test_github_pr_target_write_missing():
    """Verify that pull_request_target trigger combined with missing permissions is flagged (GPA-03)."""
    auditor = PrivilegeAuditor()
    content = """
name: PR Workflow
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
    """
    findings = auditor.scan_file(".github/workflows/pr.yml", content)
    finding_names = [f['name'] for f in findings]
    assert "github_pr_target_write" in finding_names
    assert "github_token_missing_permissions" in finding_names

def test_github_pr_target_write_excessive():
    """Verify that pull_request_target trigger combined with explicit write permissions is flagged (GPA-03)."""
    auditor = PrivilegeAuditor()
    content = """
name: PR Workflow
on:
  pull_request_target:
permissions:
  pull-requests: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
    """
    findings = auditor.scan_file(".github/workflows/pr.yml", content)
    finding_names = [f['name'] for f in findings]
    assert "github_pr_target_write" in finding_names
    assert "github_token_excessive_write" in finding_names
    assert "github_token_missing_permissions" not in finding_names

def test_mcp_root_mount():
    """Verify that MCP server mounting root or home directory is flagged (GPA-04)."""
    auditor = PrivilegeAuditor()
    
    # Valid json config
    content = """
    {
      "mcpServers": {
        "memory": {
          "command": "node",
          "args": ["dist/index.js", "/"],
          "env": {
            "DB_PATH": "~"
          }
        }
      }
    }
    """
    findings = auditor.scan_file("mcp_config.json", content)
    finding_names = [f['name'] for f in findings]
    assert "mcp_root_mount" in finding_names
    
    # Windows paths
    content_win = """
    {
      "mcpServers": {
        "file-manager": {
          "command": "node",
          "args": ["C:\\\\Users"]
        }
      }
    }
    """
    findings_win = auditor.scan_file(".cursor/mcp.json", content_win)
    assert any(f['name'] == "mcp_root_mount" for f in findings_win)

def test_mcp_elevated_execution():
    """Verify that MCP config using sudo or shell wrappers is flagged (GPA-05)."""
    auditor = PrivilegeAuditor()
    content = """
    {
      "mcpServers": {
        "admin": {
          "command": "sudo",
          "args": ["bash", "run.sh"]
        }
      }
    }
    """
    findings = auditor.scan_file("mcp_config.json", content)
    finding_names = [f['name'] for f in findings]
    assert "mcp_elevated_execution" in finding_names

def test_api_key_command_arg():
    """Verify that passing an API key as command argument is flagged (GPA-06)."""
    auditor = PrivilegeAuditor()
    
    content_sh = """
    python run.py --api-key=sk-proj-xyz123abc456xyz123abc456xyz123abc456xyz123abc456xyz
    """
    findings_sh = auditor.scan_file("deploy.sh", content_sh)
    assert any(f['name'] == "api_key_command_arg" for f in findings_sh)

def test_api_key_client_side():
    """Verify that API keys in frontend files are flagged (GPA-07)."""
    auditor = PrivilegeAuditor()
    
    # In a frontend file (e.g. index.html or config.ts in /web/)
    content_html = """
    const apiKey = "sk-proj-xyz123abc456xyz123abc456xyz123abc456xyz123abc456xyz";
    """
    findings_html = auditor.scan_file("web/src/config.ts", content_html)
    assert any(f['name'] == "api_key_client_side" for f in findings_html)
    
    # In a normal backend script (e.g. server.py), GPA-07 should NOT trigger (but normal secrets scanner can)
    findings_backend = auditor.scan_file("server.py", content_html)
    assert not any(f['name'] == "api_key_client_side" for f in findings_backend)

def test_scanner_integration(tmp_path):
    """Verify that PrivilegeAuditor runs correctly when integrated inside Scanner.scan()"""
    from ghostcheck.scanner import Scanner
    
    # Create mock workspace directories and files
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text("""
name: CI
on: [push]
# Missing permissions block
    """, encoding="utf-8")
    
    scanner = Scanner(str(tmp_path), ignore_enabled=False)
    findings = scanner.scan()
    
    # Should detect GPA-01 through scanner integration
    finding_names = [f['name'] for f in findings]
    assert "github_token_missing_permissions" in finding_names

