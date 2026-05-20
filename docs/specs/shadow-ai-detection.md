# Feature Spec: Shadow AI Detection (E7-F5)

## Overview
This feature implements the **Shadow AI Detection** module in GhostCheck. It aims to detect unauthorized or unmanaged AI software development kits (SDKs), local Large Language Model (LLM) configuration parameters, and third-party AI editor plugins in the codebase. 

By auditing these vectors, GhostCheck helps security and compliance teams enforce corporate AI policies, prevent data leakage to unapproved AI providers, and discover "shadow" local model deployments.

---

## Technical Audit Domains

### 1. Unauthorized AI SDK Imports
Developers may import third-party AI libraries to call model APIs directly from codebase without security approval.
- **Python Imports**: Scans `.py` files for import statements of known AI libraries (e.g., `import openai`, `import anthropic`, `import langchain`, `import chromadb`).
- **JavaScript/TypeScript Imports**: Scans JS/TS files for `require()` or `import` of AI npm packages (e.g., `@google/generative-ai`, `openai`, `llamaindex`, `langchain`).

### 2. Package Manifest Auditing
AI SDK dependencies declared in manifest files can bypass direct import scans if they are used dynamically.
- **Dependency Files**: Scans `package.json`, `requirements.txt`, `pyproject.toml`, `setup.py`, and `Pipfile` to detect the declaration of AI-related packages.
- **Auditing Logic**: Flags dependencies matching a comprehensive list of LLM APIs, Vector Databases, and Agent Frameworks unless explicitly allowed in configuration.

### 3. Local LLM Endpoint & Config Leakage
Developers running models locally (e.g., via Ollama, Llama.cpp, or vLLM) may hardcode local endpoints or configurations, exposing internal dev setup patterns.
- **Local Endpoints**: Flags URLs pointing to default local LLM endpoints (e.g., `http://localhost:11434`, `http://127.0.0.1:8000/v1`, `localhost:8080/v1`).
- **Environment & Variable Identifiers**: Identifies environment variable declarations or string constants containing local LLM configurations (e.g., `OLLAMA_HOST`, `OLLAMA_BASE_URL`, `VLLM_API_KEY`).

### 4. IDE Extension Configurations
AI-assisted coding extensions configured at the workspace level can automatically upload code to external services.
- **VS Code Workspace Config**: Audits `.vscode/extensions.json` to detect recommended extensions corresponding to unapproved AI coding assistants (e.g., GitHub Copilot, Tabnine, Codeium, Supermaven).

---

## Technical Architecture

### 1. The `ShadowAIDetector`
A new check module `src/ghostcheck/checks/shadow_ai.py` will be created to scan:
- Source files: `*.py`, `*.js`, `*.ts`, `*.jsx`, `*.tsx`, `*.go`, `*.java`
- Project manifests: `package.json`, `requirements.txt`, `pyproject.toml`
- Editor configurations: `.vscode/extensions.json`

### 2. Configuration Options
`ghostcheck.toml` supports custom control lists:
```toml
[shadow_ai]
allowed_sdks = ["google-generativeai"]
blocked_sdks = ["openai", "anthropic", "langchain"]
allowed_endpoints = ["https://api.approved-corp-ai.com"]
blocked_extensions = ["github.copilot", "codeium.codeium"]
```
If no config is provided, a default set of widely used AI SDKs, local LLM ports, and AI IDE plugins will be audited under the **Shadow AI audit mode**.

### 3. Rule Registry

| Rule ID | Name | Severity | Targeted Files | Description / Indicator |
|---|---|---|---|---|
| `GSA-01` | `unauthorized_ai_sdk_python` | **MEDIUM** | `*.py` | Import of unauthorized Python AI SDKs. |
| `GSA-02` | `unauthorized_ai_sdk_js` | **MEDIUM** | `*.js`, `*.ts`, `*.jsx`, `*.tsx` | Import of unauthorized JS/TS AI SDKs. |
| `GSA-03` | `unauthorized_ai_dependency` | **HIGH** | `package.json`, `requirements.txt`, etc. | Unauthorized AI package found in dependency manifests. |
| `GSA-04` | `local_llm_endpoint` | **HIGH** | Source code, `.env`, config files | Hardcoded local LLM ports/endpoints (Ollama, Llama.cpp, etc.). |
| `GSA-05` | `local_llm_env_var` | **MEDIUM** | Source code, `.env`, config files | Common local LLM environment configurations or variables. |
| `GSA-06` | `shadow_ai_ide_extension` | **LOW** | `.vscode/extensions.json` | Recommendation of unapproved AI extensions. |

---

## Verification Plan

### Automated Tests
- Test files: `tests/test_shadow_ai.py`
  - Validates detection of Python imports of OpenAI, Anthropic, and Langchain.
  - Validates detection of JavaScript imports/requires of AI packages.
  - Validates scanning of `package.json` and `requirements.txt` for AI dependencies.
  - Validates detection of local port patterns like `localhost:11434` or environment variables like `OLLAMA_HOST`.
  - Validates VS Code extensions checks.
  - Validates custom allow/block rules in configuration parsing.

### Manual Verification
- Execute `ghostcheck scan .` to run the shadow AI checks on mock workspaces.
