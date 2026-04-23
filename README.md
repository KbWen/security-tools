<div align="center">

# 👻 GhostCheck
**Blazing-fast, zero-dependency security scanner for the AI-assisted development era.**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg?style=for-the-badge)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=for-the-badge)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*Identify high-risk vulnerabilities and "ghost" threats introduced by AI agents even before they reach your CI/CD pipeline.*

<!-- SEO Keywords: security, sast, python scanner, ai-security, llm-security, mcp-audit, secrets-detection, static-analysis, owasp-llm, devsecops, cli-tool, ai-agent-security -->

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

---

## 🚀 Vision

AI agents are rewriting the world, but they also introduce new attack surfaces. **GhostCheck** bridges the gap between traditional SAST and AI-native security, ensuring your code remains secure while you move at AI speed.

## Why AgentCortex?
**GhostCheck** is built with the AgentCortex philosophy, ensuring that AI-assisted security is built on a foundation of verifiable engineering directives.

## ✨ v1.0.0 Universal Framework-Aware Scanner
*   🚀 **Framework Presets:** Automated scan strategies for **Next.js, Flutter, Django, FastAPI,** and **Terraform**.
*   🛡️ **Robust Baseline:** Content-hash based fingerprinting (`file:rule:hash`). Findings stay suppressed even if line numbers shift.
*   ⚡ **Preset-Aware Performance:** Optimized I/O by skipping irrelevant modules based on project type (e.g., ignoring Docker checks in pure Flutter apps).
*   🎯 **OWASP LLM Top 10 Report:** Industry-first `--format owasp-llm` support, mapping findings to standardized AI security categories.
*   🤖 **MCP & AI Supply Chain Audit:** Auditing for Model Context Protocol (MCP) configuration to prevent tool poisoning and excessive agency.
*   🔑 **AST-Powered Secret Detection:** Context-aware parsing for 50+ providers using language-specific AST scanners (Python, JS/TS, Go, Java, Dart).


## 🛠️ Installation & Setup

### Install via pip
Recommended for most users:
```bash
pip install ghostcheck
```

### Install from source
```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

### 2. Initialize Project Rules

Generate tailored `.ghostcheckignore` and `ghostcheck.toml` with **Automatic Framework Detection**:
```bash
ghostcheck init
```

### 3. Immediate Scan

```bash
# Scan the entire project for all risks
ghostcheck scan .

# Scan ONLY the files you are about to commit (Blazing Fast)
ghostcheck scan --staged
```

## 📋 Core Capabilities

| Feature | Command | Target |
| :--- | :--- | :--- |
| **Full Security Scan** | `ghostcheck scan` | Entire Workspace / Git Diffs |
| **Dependency Check** | `ghostcheck check-deps` | `requirements.txt`, `package.json` |
| **Secret Detection** | `ghostcheck check-secrets` | Logs, Source, Docs |
| **Rule Audit** | `ghostcheck check-rules` | `.agent/`, `.cursor/` |

## ⚙️ Configuration & CI/CD

GhostCheck respects professional workflows:

*   **Custom Exclusions:** Use `.ghostcheckignore` to silently bypass safe paths.
*   **Severity Filters:** Run scans with targeted focus using `--severity [CRITICAL|HIGH|MEDIUM|LOW]`.
*   **Multilingual Support:** Define custom safe keywords in `ghostcheck.toml` (`custom_safe_keywords = ["нельзя"]`) to prevent false positives in non-English documentation.
*   **Automation Ready:** Export results natively using `--format json`, `--format sarif` or `--format owasp-llm` for seamless compliance reporting.

---
**Developed with ❤️ for the AI community by [KbWen](https://github.com/KbWen).**
