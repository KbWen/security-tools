# 👻 GhostCheck

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](https://github.com/KbWen/security-tools)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg)](https://www.python.org/)

**GhostCheck** is a high-performance, zero-dependency security scanner engineered for the AI-assisted development era. It identifies high-risk vulnerabilities and "ghost" threats introduced by AI agents even before they reach your CI/CD pipeline.

---

## 🚀 Vision

AI agents are rewriting the world, but they also introduce new attack surfaces. **GhostCheck** bridges the gap between traditional SAST and AI-native security, ensuring your code remains secure while you move at AI speed.

## ✨ Key Features (v0.3.0)

- **Deep Intelligence Scanning**:
  - **AST-Based Secret Detection**: Uses Abstract Syntax Tree parsing to detect obfuscated secrets formed through string concatenation in Python files.
  - **Offline Mode & Local Cache**: Blazing-fast repeated scans with local package metadata caching (up to 24h) and `--offline` support for air-gapped environments.
- **Advanced Agent Rule Linting**: Detects complex behavioral risks like data exfiltration (POST/DNS), hidden tunneling (ngrok/ssh), and logic bypasses in agent instruction files.
- **Improved Scanner Engine**: Robust modular design supporting both directory and single-file targets.
- **Git Hook Integration**: Professional pre-commit hooks for Windows (PowerShell) and Unix (Shell) to block risky commits.
- **Docker Risk Check**: Detects privileged containers, root execution, and insecure port mappings in Dockerfiles.
- **Hallucination Protection**: Verifies dependency legitimacy against PyPI and npm registries.
- **Professional Reporting**: Structured tabular output with severity color-coding and executive summaries.

## 🛠️ Quick Start

### Installation

```bash
pip install -e .
```

### Immediate Scan

```bash
# Scan entire project for all risks
ghostcheck scan .

# Run interactive simulation to see it in action
ghostcheck demo
```

## 📋 Commands & Features

| Feature | Commands | Target |
| :--- | :--- | :--- |
| **Full Security Scan** | `ghostcheck scan` | Entire Workspace |
| **Dependency Check** | `ghostcheck check-deps` | `requirements.txt`, `package.json` |
| **Secret Detection** | `ghostcheck check-secrets` | Logs, Source, Docs |
| **Rule Audit** | `ghostcheck check-rules` | `.agent/`, `.cursor/` |

## ⚙️ Configuration

GhostCheck respects professional ignore rules:
- Create a `.ghostcheckignore` to exclude specific paths.
- Filter results by severity using `--severity [CRITICAL|HIGH|MEDIUM|LOW]`.
- Export results for automation using `--format json`.

---

**Developed with ❤️ for the AI community by [KbWen](https://github.com/KbWen).**
