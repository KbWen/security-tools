# Archive Index

Index of all archived work logs, categorized by module, pattern, and key decisions.

## By Module

- `tests/test_antigravity_verification.py` → `test-antigravity-test-20260605.md` (Antigravity 2.0 integration and runtime verification test)
- `.agentcortex/bin/validate.*` → `test-antigravity-test-20260605.md` (Resolved README_zh-TW.md canary validation failures in CI scripts)
- `src/ghostcheck/checks/context_auditor.py` → `fix-fp-reduction-and-context-intelligence.md` (Context Intelligence layer added for FP reduction)
- `src/ghostcheck/checks/privilege_auditor.py` → `feat-agent-least-privilege-audit.md` (Agent Least Privilege Audit checker implemented)
- `src/ghostcheck/checks/prompt_template_scanner.py` → `feat-older-issues-bundle.md` (Implemented Prompt Template Injection Scanner plugin)
- `src/ghostcheck/checks/ai_marker.py` → `feat-older-issues-bundle.md` (Implemented AI-Generated Code Marker plugin)
- `src/ghostcheck/checks/` → `fix-bug-bundle.md` (Resolved outstanding bugs in diff scanner, severity engine, mcp auditor, entropy scanner, and hallucination checker)
- `src/ghostcheck/checks/data_exfiltration_detector.py` → `feat-data-exfiltration.md` (AI Data Exfiltration Detector checking LLM prompt, MCP tool leakage, and public writes)
- `src/ghostcheck/checks/context_inflation_detector.py` → `feat-context-inflation-20260701.md` (Context Inflation / Prompt Flooding Detector scanner plugin)
- `src/ghostcheck/presets/manager.py` → `feat-context-inflation-20260701.md` (Integrated context_inflation into Next.js, Flutter, Django, FastAPI, Terraform presets)
- `src/ghostcheck/ignorefile.py`, `src/ghostcheck/checks/secrets.py`, `src/ghostcheck/cli.py` → `ship-main-pre-mortem-and-expert-hardening-2026-08-14.md` (Pre-Mortem, Tenth Man, and Expert Peer Review Hardening)

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
- `[prompt-template-injection]` → `feat-older-issues-bundle.md`
- `[ai-code-marking]` → `feat-older-issues-bundle.md`
- `[git-audit-hardening]` → `feat-older-issues-bundle.md`
- `[data-exfiltration]` → `feat-data-exfiltration.md`
- `[shannon-entropy-refinement]` → `feat-data-exfiltration.md`
- `[ts-syntax-fallback]` → `feat-data-exfiltration.md`
- `[context-inflation]` → `feat-context-inflation-20260701.md`
- `[n-gram-performance]` → `feat-context-inflation-20260701.md`
- `[ignore-ssot-centralization]` → `ship-main-pre-mortem-and-expert-hardening-2026-08-14.md`
- `[secrets-extension-blindspot]` → `ship-main-pre-mortem-and-expert-hardening-2026-08-14.md`

## By Decision

- `[canary-phrase-update]` → Updated README_zh-TW.md canary phrase to '安全性掃描工具' to align with the rewritten doc structure (`test-antigravity-test-20260605.md`)
- `[multilingual-keywords]` → Loaded dynamically from JSON with fallbacks (`fix-fp-reduction-and-context-intelligence.md`)
- `[regex-negative-lookbehinds]` → Distinguish script files from commands (`fix-fp-reduction-and-context-intelligence.md`)
- `[mcp-json-fallback]` → Line-based scanning fallback on JSON decode failures (`feat-agent-least-privilege-audit.md`)
- `[client-side-api-key-detection]` → Front-end key detection restricted to client paths/extensions to prevent backend false positives (`feat-agent-least-privilege-audit.md`)
- `[plugin-decoupling]` → Scanners and Reporters abstracted to base classes (`feat-shadow-ai-detection.md`)
- `[scoped-package-quote]` → Force URL-encoding with safe='' for NPM scoped packages to prevent 404 registry checks (`fix-bug-bundle.md`)
- `[kebab-case-false-positives]` → Ignore kebab-case strings in entropy scanner if they consist of purely alphabetic/short-numeric words (`fix-bug-bundle.md`)
- `[windows-binary-planting-mitigation]` → Resolved Windows binary planting (CWE-427) via absolute resolved git executable path and `-C` flag (`feat-older-issues-bundle.md`)
- `[spoof-proof-git-delimiter]` → Used ASCII control characters `\x1f` and `\x1e` as separators in git log formatting to prevent commit message spoofing (`feat-older-issues-bundle.md`)
- `[scanner-preset-registration]` → Automatically registered `supply_chain` module in Next.js, Django, FastAPI, and Flutter presets (`feat-older-issues-bundle.md`)
- `[comment-evasion-preprocessor]` → Strip comments while preserving character offsets in APILinter and LogicAuditor to resolve false positives and prevent evasion (`feat-older-issues-bundle.md`)
- `[dynamic-test-key-generation]` → Dynamically construct mock API keys at test runtime to prevent triggering GitHub Advanced Security Secret Scanning alerts (`feat-older-issues-bundle.md`)
- `[shannon-entropy-key-token-filter]` → Run Shannon entropy checking only on regex-filtered key token matches to prevent false positives on CJK natural languages (`feat-data-exfiltration.md`)
- `[typescript-syntax-fallback-scanning]` → Gracefully fallback to text-based scanning on typescript AST parsing failures (`feat-data-exfiltration.md`)
- `[ngram-repetition-optimized-comparison]` → Use index-based sliding comparisons for n-gram checks instead of full list comprehension tuple allocations to ensure O(1) memory complexity (`feat-context-inflation-20260701.md`)
- `[zw-unicode-isolates-expansion]` → Include bidirectional isolates (\u2066–\u2069), word joiners, and Mongolian vowel separators to prevent Trojan Source-style prompt injection bypasses (`feat-context-inflation-20260701.md`)
- `[ignore-ssot-centralization]` → Centralize default directory ignores in IgnoreMatcher SSoT to preserve negation rules (`ship-main-pre-mortem-and-expert-hardening-2026-08-14.md`)
- `[secrets-extension-blindspot]` → Add .tsx, .jsx, .toml, .tf to SecretScanner allowed_exts to close React/Cloud scanning gaps (`ship-main-pre-mortem-and-expert-hardening-2026-08-14.md`)

