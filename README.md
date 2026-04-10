<div align="center">

# 👻 GhostCheck
**Blazing-fast, zero-dependency security scanner for the AI-assisted development era.**

[![Version](https://img.shields.io/badge/version-0.9.0-blue.svg?style=for-the-badge)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=for-the-badge)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*Identify high-risk vulnerabilities and "ghost" threats introduced by AI agents even before they reach your CI/CD pipeline.*

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

---

## 🚀 Vision

AI agents are rewriting the world, but they also introduce new attack surfaces. **GhostCheck** bridges the gap between traditional SAST and AI-native security, ensuring your code remains secure while you move at AI speed.

## Why AgentCortex?
**GhostCheck** is built with the AgentCortex philosophy, ensuring that AI-assisted security is built on a foundation of verifiable engineering directives.

## ✨ v0.9.0 Performance & Security Milestones

*   🚀 **High-Performance Parallel Engine:** Leveraging `ThreadPoolExecutor` and a single-pass dispatch architecture. Scan speeds for large projects have been boosted significantly.
*   🛡️ **Red Team Hardened:** Fixed path traversal vulnerabilities and implemented automatic "redaction-at-rest" for scan reports, ensuring scanner output doesn't become a leak source.
*   🔑 **Expanded Secret Detection:** Out-of-the-box detection for 30+ providers (AWS, GCP, Stripe, GitHub, Slack, etc.) using context-aware AST parsing.
*   🖥️ **Encoding Resilience:** Automatic stdout reconfiguration for Windows (CP950) terminals to prevent crashes when printing high-fidelity security icons.
*   🤖 **MCP & AI Supply Chain Audit:** Industry-first support for Model Context Protocol (MCP) configuration auditing to prevent tool poisoning and excessive agency.

## 🛠️ Quick Start

### 1. Installation

```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

### 2. Initialize Project Rules

Generate tailored `.ghostcheckignore` and `ghostcheck.toml` setups instantly:
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
*   **Automation Ready:** Export results natively using `--format json` or `--format sarif` for seamless GitHub Advanced Security integration.

---
**Developed with ❤️ for the AI community by [KbWen](https://github.com/KbWen).**
