div align="center">

# 👻 GhostCheck

**Blazing-fast, zero-dependency security scanner for the AI-assisted development era.**

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg?style=flat-square)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=flat-square)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Tests Status](https://img.shields.io/badge/tests-105%20passed-brightgreen.svg?style=flat-square)](LICENSE)

*Identify high-risk vulnerabilities, malicious directives, and "ghost" security threats introduced by AI agents before they reach your CI/CD pipeline.*

---

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

## 🚀 Vision

AI agents are rewriting the world, but they also introduce new attack surfaces. **GhostCheck** bridges the gap between traditional Static Application Security Testing (SAST) and AI-native security. It ensures your codebase remains secure while you move at the speed of AI.

---

## 🧠 Why AgentCortex?

**GhostCheck** is built upon the **AgentCortex** philosophy, which asserts that AI-assisted software engineering must be guided by **verifiable engineering directives**. 

Traditional scanners look for standard developer bugs (like SQL injection or buffer overflows). In the AI era, we face new threats:
*   **Excessive Agency:** AI tools executing arbitrary commands with root privileges.
*   **Tool Poisoning:** Malicious third-party tools (e.g. MCP servers) hijacking the agent.
*   **Instruction Injection:** Hidden directives in files designed to compromise agent behavior.
*   **AI Supply Chain Vulnerabilities:** Hallucinated package references and malicious dependencies.

By anchoring your project conventions in verifiable constraints, GhostCheck ensures AI agents behave as secure, reliable co-designers.

---

## ✨ Key Features & Highlights

### 🔌 v1.0.3: Extensible Plugins & Red Team Hardening
*   **Plugin-Based Architecture:** Scanners and reporters are fully decoupled, making it simple to write custom logic.
*   **Red Team Hardened:** Built-in protection against chaos tests, bypass attempts, local Remote Code Execution (RCE) vectors, and directory traversal.
*   **Universal Reporters:** Native support for `console`, `json`, `html`, `owasp-llm`, and `sarif` outputs.
*   **Shannon Entropy Generic Secret Filtering:** Added Shannon entropy checks to detect high-entropy keys/passwords while minimizing false positives for structured keys.
*   **Comment-Aware Shadow AI Exclusions:** Parsing engine now respects code comments (`//`, `#`, etc.) to selectively exclude designated lines or blocks from AI security audit scans.
*   **Casing-Insensitive Mobile CI Config Filters:** Mobile pipeline scanners (Android/iOS CI) now support case-insensitive pattern matching for configurations and environment variables.
*   **Pre-Filter Scoping I/O Optimizations:** High-performance pre-filtering checks file types and scopes before performing heavy I/O operations, reducing unnecessary reads on large codebases.

### 🎯 v1.0.0: Universal Framework-Aware Scanner
*   **Framework Presets:** Automated scan strategies tailored for **Next.js, Flutter, Django, FastAPI,** and **Terraform**.
*   **Robust Baseline & Suppression:** Content-hash based fingerprinting (`file:rule:hash`). Suppressed warnings stay suppressed even if line numbers shift.
*   **Preset-Aware Performance:** Optimized I/O by skipping irrelevant modules based on project type (e.g., ignoring Docker checks in pure Flutter apps).
*   **OWASP LLM Top 10 Report:** Industry-first `--format owasp-llm` support, mapping findings to standardized AI security categories.
*   **MCP & AI Supply Chain Audit:** Audits Model Context Protocol (MCP) configurations to prevent tool poisoning and excessive agency.
*   **AST-Powered Secret Detection:** Context-aware parsing for 50+ providers using language-specific AST scanners (Python, JS/TS, Go, Java, Dart).

---

## 📋 Core Capabilities & Command Reference

GhostCheck provides dedicated commands to check specific risk vectors:

| Capability | Command | Target | Description |
| :--- | :--- | :--- | :--- |
| **Full Security Scan** | `ghostcheck scan` | Entire Workspace / Git Diffs | Scans for secrets, IAC misconfigurations, and agent rules. |
| **Dependency Check** | `ghostcheck check-deps` | `requirements.txt`, `package.json` | Detects hallucinated packages or vulnerable dependencies. |
| **Secret Detection** | `ghostcheck check-secrets` | Logs, Source, Docs | Identifies API keys, tokens, and credentials via AST parsing. |
| **Rule Audit** | `ghostcheck check-rules` | `.agent/`, `.cursor/`, `.agentcortex/` | Validates agent instructions against privilege escalation/tampering. |

---

## 🛠️ Installation & Setup

### 📦 Option A: Install via PyPI (Standard)
Recommended for most users to get the latest stable release:
```bash
pip install ghostcheck
```

### 🔨 Option B: Install from Source
To run or test the latest features directly from the repository:
```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

### 💻 Option C: Developer & Contributor Setup
If you are developing plugins, extending rule presets, or running tests:
1. Clone the repository and navigate to the project directory:
   ```bash
   git clone https://github.com/KbWen/security-tools.git
   cd security-tools
   ```
2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On macOS/Linux:
   source .venv/bin/activate
   ```
3. Install package with development dependencies in editable mode:
   ```bash
   pip install -e ".[dev]"
   # Or using the Makefile:
   make install
   ```

---

## 🚀 Quick Start Guide

### 1. Initialize Project Rules
Generate a tailored `.ghostcheckignore` and `ghostcheck.toml` configuration with **Automatic Framework Detection**:
```bash
ghostcheck init
```

### 2. Run an Immediate Scan
Scan the workspace for any vulnerabilities:
```bash
# Scan the entire project for all risks
ghostcheck scan .

# Scan ONLY the files you are about to commit (Blazing Fast for pre-commit)
ghostcheck scan --staged
```

---

## 🧪 Running Tests & Verification

Verify that your installation is complete and all core scanners are functioning correctly by running the suite of 105 unit and integration tests.

### Using Pytest
With your virtual environment active, execute `pytest`:
```bash
pytest tests/ -v
```

### Using Makefile (macOS/Linux)
```bash
make test
```

Expected output should show all tests passing:
```text
============================= 105 passed in 3.95s =============================
```

---

## ⚙️ Configuration & CI/CD Integration

GhostCheck respects professional workflows and offers fine-grained configuration:

*   **Custom Exclusions:** Use `.ghostcheckignore` to silently bypass safe paths or test fixtures.
*   **Severity Filters:** Run scans with a targeted focus using `--severity [CRITICAL|HIGH|MEDIUM|LOW]`.
*   **Multilingual Support:** Define custom safe keywords in `ghostcheck.toml` (e.g., `custom_safe_keywords = ["нельзя"]` or `custom_safe_keywords = ["避免"]`) to prevent false positives in non-English documentation.
*   **Automation & Reports:** Export results natively using `--format json`, `--format html`, `--format sarif`, or `--format owasp-llm` for seamless integration into GitHub Actions, GitLab CI/CD, and compliance tools.

---

## 📄 License

This project is licensed under the MIT License - see the local [LICENSE](LICENSE) file for details.

---

<div align="center">

**Developed with ❤️ for the AI community by [KbWen](https://github.com/KbWen).**

</div>
