# Archive Index

Index of all archived work logs, categorized by module, pattern, and key decisions.

## By Module

- `tests/test_antigravity_verification.py` → `test-antigravity-test-20260605.md` (Antigravity 2.0 integration and runtime verification test)
- `.agentcortex/bin/validate.*` → `test-antigravity-test-20260605.md` (Resolved README_zh-TW.md canary validation failures in CI scripts)
- `src/ghostcheck/checks/context_auditor.py` → `fix-fp-reduction-and-context-intelligence.md` (Context Intelligence layer added for FP reduction)
- `src/ghostcheck/checks/privilege_auditor.py` → `feat-agent-least-privilege-audit.md` (Agent Least Privilege Audit checker implemented)
- `src/ghostcheck/plugins/*` → `feat-shadow-ai-detection.md` (Reporter decoupling and Red Team hardening)
- `src/ghostcheck/checks/` → `fix-bug-bundle.md` (Resolved outstanding bugs in diff scanner, severity engine, mcp auditor, entropy scanner, and hallucination checker)

## By Pattern

- `[antigravity-verification]` → `test-antigravity-test-20260605.md`
- `[ci-validation-fix]` → `test-antigravity-test-20260605.md`
- `[fp-reduction]` → `fix-fp-reduction-and-context-intelligence.md`
- `[multilingual-config]` → `fix-fp-reduction-and-context-intelligence.md`
- `[least-privilege]` → `feat-agent-least-privilege-audit.md`
- `[mcp-security]` → `feat-agent-least-privilege-audit.md`
- `[plugin-architecture]` → `feat-shadow-ai-detection.md`
- `[red-team-hardening]` → `feat-shadow-ai-detection.md`
- `[bug-fix-bundle]` → `fix-bug-bundle.md`
- `[scoped-pkg-encoding]` → `fix-bug-bundle.md`
- `[kebab-case-exclusion]` → `fix-bug-bundle.md`

## By Decision

- `[canary-phrase-update]` → Updated README_zh-TW.md canary phrase to '安全性掃描工具' to align with the rewritten doc structure (`test-antigravity-test-20260605.md`)
- `[multilingual-keywords]` → Loaded dynamically from JSON with fallbacks (`fix-fp-reduction-and-context-intelligence.md`)
- `[regex-negative-lookbehinds]` → Distinguish script files from commands (`fix-fp-reduction-and-context-intelligence.md`)
- `[mcp-json-fallback]` → Line-based scanning fallback on JSON decode failures (`feat-agent-least-privilege-audit.md`)
- `[client-side-api-key-detection]` → Front-end key detection restricted to client paths/extensions to prevent backend false positives (`feat-agent-least-privilege-audit.md`)
- `[plugin-decoupling]` → Scanners and Reporters abstracted to base classes (`feat-shadow-ai-detection.md`)
- `[scoped-package-quote]` → Force URL-encoding with safe='' for NPM scoped packages to prevent 404 registry checks (`fix-bug-bundle.md`)
- `[kebab-case-false-positives]` → Ignore kebab-case strings in entropy scanner if they consist of purely alphabetic/short-numeric words (`fix-bug-bundle.md`)
