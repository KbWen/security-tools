<div align="center">

# 👻 GhostCheck
**High-performance, zero-dependency security scanner for the AI-assisted development era.**

[![Version](https://img.shields.io/badge/version-0.6.0-blue.svg?style=for-the-badge)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=for-the-badge)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*Identify high-risk vulnerabilities and "ghost" threats introduced by AI agents even before they reach your CI/CD pipeline.*

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

---

## 🚀 Vision

AI agents are rewriting the world, but they also introduce new attack surfaces. **GhostCheck** bridges the gap between traditional SAST and AI-native security, ensuring your code remains secure while you move at AI speed.

## ✨ What's New in v0.6.0?

*   🎯 **Zero-Config Onboarding:** Run `ghostcheck init` to instantly generate best-practice security rules for your stack.
*   🔍 **Smart Git Integration:** Scan only what matters. Support for scanning staged files (`ghostcheck scan --staged`) and uncommitted diffs (`--diff`).
*   🔑 **Expanded Secret Detection:** Out-of-the-box detection for 30+ providers (AWS, GCP, Stripe, GitHub, Slack, etc.) using context-aware AST parsing.
*   🛡️ **Frictionless Suppression:** Manage false positives elegantly via `ghostcheck.toml` baseline ignores or inline `# ghostcheck:disable` comments.
*   ⚡ **uv-Powered:** Optimized CI pipelines with 10x faster matrix testing and dependency resolution using `uv`.

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
