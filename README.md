# 👻 GhostCheck

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/KbWen/security-tools)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg)](https://www.python.org/)

**GhostCheck** is a high-performance, zero-dependency security scanner engineered for the AI-assisted development era. It identifies high-risk vulnerabilities and "ghost" threats introduced by AI agents even before they reach your CI/CD pipeline.

---

## 🚀 Vision

AI agents are rewriting the world, but they also introduce new attack surfaces. **GhostCheck** bridges the gap between traditional SAST and AI-native security, ensuring your code remains secure while you move at AI speed.

## ✨ Key Features (v0.2.0)

- **Advanced Secret Scanning**: High-precision regex for AWS, GCP, GitHub, Slack, and Stripe keys. **Now scans across all code files** (.py, .js, .ts, etc.).
- **Git Hook Integration**: Professional pre-commit hooks for Windows (PowerShell) and Unix (Shell) to block risky commits.
- **Rogue Agent Detection**: Identifies dangerous behavioral patterns (exfiltration, logic bypasses) in agent instruction files.
- **Docker Risk Check**: Detects privileged containers, root execution, and insecure port mappings in Dockerfiles.
- **Hallucination Protection**: Verifies dependency legitimacy against PyPI and npm registries.
- **Professional Reporting**: Structured tabular output with severity color-coding and executive summaries.
- **Extensible Architecture**: Modular design for adding custom domain-oriented security checks.

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
