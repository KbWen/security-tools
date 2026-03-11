# GhostCheck

**GhostCheck** is a CLI security scanner designed for AI-assisted development workflows. It addresses risks that traditional tools miss: hallucinated packages, leaked secrets in AI chat logs, and dangerous agent instruction configurations.

## Features

- 🦄 **Hallucination Detection**: Identify nonexistent packages on PyPI/npm.
- 🔑 **Smart Secret Scanning**: Detect keys in AI logs with file-type-aware severity.
- 🛡️ **Agent Rules Linter**: Scan `.agent/`, `.cursor/`, and `.github/` for risky rules.
- 🚫 **Ignore Support**: Exclude paths via `.ghostcheckignore`.
- 🚀 **Demo Mode**: Instant "wow" experience with `ghostcheck demo`.

## Installation

```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

## Quick Start

```bash
# Run a demo scan with sample vulnerabilities
ghostcheck demo

# Scan the current directory
ghostcheck scan .

# Check dependencies for hallucinations
ghostcheck check-deps requirements.txt
```

## Configuration

### .ghostcheckignore

Create a `.ghostcheckignore` file in your project root to exclude files:

```text
# Ignore log files
*.log
# Ignore dependency folder
node_modules/
```

## License

MIT
