---
status: frozen
---

# Feature Spec: Agent Least Privilege Audit (E7-F2)

## Overview
This feature implements the **Agent Least Privilege Audit** module in GhostCheck. It targets the auditing of environment tokens, API keys, CI configurations, and Model Context Protocol (MCP) server permission boundaries to ensure they adhere to the Principle of Least Privilege (PoLP).

By identifying over-privileged tokens (such as `GITHUB_TOKEN` with write access where read-only suffices) and overly broad MCP configurations (such as mounting the root directory or running with administrative privileges), the tool reduces the attack surface of AI agents.

---

## Technical Audit Domains

### 1. GitHub Workflows (`GITHUB_TOKEN` Permissions)
GitHub Actions workflows run with a default `GITHUB_TOKEN` whose permissions depend on repository settings (often defaulting to read/write).
- **Default Permissions Check**: Audits if `permissions:` block is entirely missing from a workflow file, which defaults to permissive read/write scopes in older or loosely configured repos.
- **Over-privileged Scopes**: Flags jobs that declare `write` scopes for resources that typically only require `read` (e.g., `contents: write`, `actions: write`, `issues: write`) unless the workflow is explicitly recognized as a release/publishing flow.
- **Elevation Detection**: Flags workflows that run on `pull_request_target` while requesting write permissions or secrets, as this combination is highly vulnerable to prompt injection and malicious PR attacks.

### 2. MCP Configuration Permission Auditing
Model Context Protocol configurations define how AI IDEs interface with local tools.
- **Sudo / Administrative Commands**: Flags MCP server executions that use `sudo`, run as `root`, or invoke command shells (`bash`, `sh`, `cmd`, `powershell`) with arbitrary user parameters.
- **Root Directory Mounting**: Flags MCP tool configurations that mount/bind host root directory `/` or user home directory `~` instead of restricting boundaries to the workspace folder.
- **Excessive Tools Capability**: Audits if the server is granted read/write capabilities (`fs.writeFile`, etc.) but only requires read-only scopes.

### 3. LLM API Key Privilege Audit
- **Client-Side Key Leakage**: Detects if LLM keys (OpenAI, Anthropic, Gemini) are exposed in frontend client-side source code (e.g., React, Vue, HTML, Javascript bundles).
- **Insecure Key Transport**: Flags cases where API keys are passed via command-line arguments (e.g. `--api-key`) in shell configurations or scripts, exposing them in process tables (`ps aux`).

---

## Technical Architecture

### 1. The `PrivilegeAuditor`
A new check module `src/ghostcheck/checks/privilege_auditor.py` will be created to scan:
- `.github/workflows/*.yml` / `.github/workflows/*.yaml`
- `mcp_config.json`, `mcp.json`, `.cursor/mcp.json`
- Python/JS/TS/Shell script files defining environment variables or API execution configs.

### 2. Rule Registry
Rules are registered in the privilege auditor:

| Rule ID | Name | Severity | Targeted Files | Description / Indicator |
|---|---|---|---|---|
| `GPA-01` | `github_token_missing_permissions` | **MEDIUM** | `.github/workflows/*.yml` | Workflow lacks explicit `permissions:` block. |
| `GPA-02` | `github_token_excessive_write` | **HIGH** | `.github/workflows/*.yml` | Excessive `write` permissions assigned (e.g. `actions: write`). |
| `GPA-03` | `github_pr_target_write` | **CRITICAL** | `.github/workflows/*.yml` | Write permissions requested on a `pull_request_target` trigger. |
| `GPA-04` | `mcp_root_mount` | **CRITICAL** | `mcp_config.json`, `mcp.json` | Path arguments pointing to `/` or home directory `~`. |
| `GPA-05` | `mcp_elevated_execution` | **HIGH** | `mcp_config.json`, `mcp.json` | Commands using `sudo`, `runas`, or starting raw shell processes. |
| `GPA-06` | `api_key_command_arg` | **HIGH** | `*.sh`, `*.bat`, `*.py`, `*.js` | API key strings passed via argv/cmd line options. |
| `GPA-07` | `api_key_client_side` | **CRITICAL** | `src/`, `web/`, frontend files | API key hardcoded in frontend JS/HTML code. |

---

## Verification Plan

### Automated Tests
- Test files: `tests/test_privilege_auditor.py`
  - Validates correct flagging of missing `permissions:` blocks in YAML.
  - Validates detection of `pull_request_target` combined with write permissions.
  - Validates flagging of MCP configurations attempting root mounting or using `sudo`.
  - Validates API key argument exposure and frontend client-side leaks.

### Manual Verification
- Execute `ghostcheck scan .` to run the new checks on mock setups in the tests directory.
