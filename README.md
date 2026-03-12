# 👻 GhostCheck

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/KbWen/security-tools)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg)](https://www.python.org/)

**GhostCheck** is a high-performance, zero-dependency security scanner engineered for the AI-assisted development era. It identifies high-risk vulnerabilities and "ghost" threats introduced by AI agents even before they reach your CI/CD pipeline.

---

## 🚀 Vision

AI agents are rewriting the world, but they also introduce new attack surfaces. **GhostCheck** bridges the gap between traditional SAST and AI-native security, ensuring your code remains secure while you move at AI speed.

## 🛡️ Core Capabilities

- **🔍 Hallucination Detection**: Automatically verifies dependencies to flag AI-hallucinated packages before they are installed.
- **🔑 Context-Aware Secret Scanning**: Specialized detection for API keys and tokens in terminal logs, AI chat history, and source code.
- **📜 Agent Rules Linter**: Audits `.agent`, `.cursorrules`, and other instructions for dangerous permissions or command execution risks.
- **⚡ Zero Infrastructure**: A single-file, pure Python engine. No database, no Docker, no external APIs required.

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
