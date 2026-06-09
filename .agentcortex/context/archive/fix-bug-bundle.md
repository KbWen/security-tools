# Work Log: fix-bug-bundle

- Branch: fix/bug-bundle
- Classification: quick-win
- Classified by: Antigravity
- Frozen: true
- Created Date: 2026-06-08
- Owner: wen
- Guardrails Mode: Quick
- Recommended Skills: systematic-debugging (Resolving crashes and regex bugs), verification-before-completion (Verifying fixes via tests)

## Session Info
- Agent: Antigravity (Gemini 3.5 Flash)
- Session: 2026-06-08T12:25:00+08:00
- Platform: Antigravity

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO

## Risks (from /plan)
- [git-diff-regression]: Regression in git diff parsing if path resolution has directory vs file mismatch. Mitigation: verified directory resolution with test cases.
- [registry-encoding-failure]: URL encoding could alter registry URLs for standard packages. Mitigation: verified PyPI/NPM endpoints with test suite.
- [entropy-bypass]: Exclusion of kebab-case could accidentally bypass real hyphenated secrets. Mitigation: restricted exclusion to purely alphabetic/short-numeric segments.

## Adversarial Security Audit (Peer Review)
Dispatched two parallel subagents to conduct an adversarial review of all changes:
1. **supply-chain-auditor** (`675e28c5-df54-4881-80b5-a193fb3c234f`): Identified encoding failures on scoped packages (need `safe='@'`), escape/port bypasses on MCP host bindings, and unicode path resolution issues (`core.quotePath`).
2. **severity-and-entropy-auditor** (`50492dd9-3c1f-4198-8bc2-33f327e96c32`): Identified potential bypasses on kebab-case exclusions (need lowercase + length limits), downstream crash risks from invalid file paths, and score calculation bypasses on custom severities.

## Hardening Fixes
1. **git_diff_scanner.py**: Configured Git commands with `-c core.quotePath=false` to support non-ASCII filenames, resolved absolute paths to prevent empty `cwd`, and stripped quotes from git stdout.
2. **hallucination.py**: Fixed NPM scoped package encoding to use `safe='@'` (`@types%2Fnode`), and filtered out local files, git URLs, and external protocols before registry checks.
3. **mcp_auditor.py**: Upgraded wildcard regex to detect port numbers, alternative config keys (`bind`/`listen`), and multiple IPv6 representations.
4. **entropy_scanner.py**: Restructured kebab-case exclusions to enforce lowercase, maximum token length $\le 40$, maximum 5 segments, and segment word lengths $\le 12$ to prevent key leakage.
5. **scoring.py**: Normalized invalid/custom severities (like `WARNING`, `ERROR`, `FATAL`) to standard levels so they are penalized properly.
6. **scanner.py**: Sanitized raw findings at loop entry, forcing `file` to be a string and `severity` to be uppercase to prevent downstream type-mismatch crashes.

## Verification Evidence
- Added 3 new unit tests targeting custom severities, scanner sanitization, and kebab-case bypass scenarios.
- Ran pytest suite: `.venv\Scripts\pytest` (112/112 tests passed).
- Ran CLI scan: `.venv\Scripts\python -m ghostcheck.cli scan .` (Successful scan run, no crashes).

## Security Findings
- No critical/high security issues introduced in the changed files. Checked A01, A02, A03, and secrets.

## Lessons
- None.

## Status
- All changes completed, verified, and successfully archived.
