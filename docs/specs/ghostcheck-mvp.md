---
status: frozen
module: ghostcheck
created: 2026-03-11
---
# GhostCheck MVP Specification

## Overview

GhostCheck is a CLI security scanner designed for AI-assisted development workflows.
It detects security risks that traditional scanners miss: hallucinated packages,
leaked secrets in AI outputs, and dangerous agent rule configurations.

## Architecture

```
src/ghostcheck/
├── __init__.py              # Version: "0.1.0"
├── cli.py                   # argparse CLI entry point
├── scanner.py               # Orchestrator
├── checks/
│   ├── __init__.py
│   ├── hallucination.py     # Package hallucination detector
│   ├── secrets.py           # Secret leak scanner
│   └── agent_rules.py       # Agent rules linter
├── reporters/
│   ├── __init__.py
│   ├── console.py           # ANSI colored terminal output
│   └── json_reporter.py     # JSON export
└── data/
    ├── secret_patterns.json # Regex patterns for secrets
    └── risky_rules.json     # Risk patterns for agent rules
```

## Acceptance Criteria

### AC-1: Full Scan
`ghostcheck scan <path>` runs all three check modules against the target path and
outputs a combined report. Default format is console.

### AC-2: Dependency Check (Python)
`ghostcheck check-deps requirements.txt` parses the file, queries PyPI API for each
package, and flags: CRITICAL if package doesn't exist (404), HIGH if < 30 days old
or < 50 weekly downloads, MEDIUM if < 90 days old or < 500 weekly downloads.

### AC-3: Dependency Check (npm)
`ghostcheck check-deps package.json` parses dependencies and devDependencies,
queries npm registry, applies same age/download thresholds as Python.

### AC-4: Secret Scanner
`ghostcheck check-secrets <path>` recursively scans .md, .json, .txt, .log, .yaml,
.yml files for patterns matching API keys, tokens, passwords, connection strings,
and private keys. Excludes false positives containing "example", "placeholder",
"xxx", "your-key-here", "TODO". Reports file, line number, pattern name, masked value.

### AC-5: Agent Rules Linter
`ghostcheck check-rules <path>` scans agent config directories (.agent/, .agents/,
.cursor/, .github/copilot/) for risky patterns: destructive commands (rm -rf,
DROP TABLE), privilege escalation (sudo, chmod 777), external execution (curl|bash),
hardcoded secrets, overly permissive rules, disabled safety checks.

### AC-6: Severity Levels
All findings include severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.
CLI flag `--severity <level>` filters output to show only findings at or above threshold.

### AC-7: Output Formats
`--format console` (default): colored terminal output with summary and details.
`--format json`: machine-readable JSON array of findings.

### AC-8: Exit Codes
Exit 0 = no findings, Exit 1 = findings found, Exit 2 = runtime error.

### AC-9: Test Coverage
All check modules have unit tests. Tests use mocked HTTP responses (no real network
calls in tests). Fixtures provide realistic sample files. Target: ≥80% line coverage
on core check modules.

### AC-10: English Documentation
`docs/ghostcheck/README.md` covers: project description, installation, quick start,
all commands with examples, CI integration guide, contributing section.

### AC-11: Chinese Documentation
`docs/ghostcheck/README_zh-TW.md` provides equivalent content in 繁體中文.

### AC-12: Packaging
`pyproject.toml` with no runtime dependencies. CLI entry point registered.
`pip install -e .` works. GitHub Actions CI runs tests on Python 3.9-3.12.

## Non-goals

- LLM integration / AI-powered fix suggestions (deferred to v2)
- Git patch generation
- Real-time file watching / daemon mode
- Web UI or desktop GUI
- Support for languages beyond Python/npm for dependency checking
- SBOM generation

## Risks

1. PyPI/npm API rate limiting during dependency checks → Mitigation: 0.5s delay between requests, timeout handling
2. Regex patterns for secret detection may have false positives → Mitigation: configurable exclusion list
3. Agent rules analysis is pattern-based, not semantic → Mitigation: clearly document limitations

## Constraints

- Python ≥3.9
- Zero external runtime dependencies (stdlib only)
- Dev dependencies: pytest, pytest-cov
- Must work on Windows, macOS, and Linux
