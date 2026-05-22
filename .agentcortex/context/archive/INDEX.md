# Archive Index

Index of all archived work logs, categorized by module, pattern, and key decisions.

## By Module

- `src/ghostcheck/checks/context_auditor.py` → `fix-fp-reduction-and-context-intelligence.md` (Context Intelligence layer added for FP reduction)
- `src/ghostcheck/checks/privilege_auditor.py` → `feat-agent-least-privilege-audit.md` (Agent Least Privilege Audit checker implemented)
- `src/ghostcheck/plugins/*` → `feat-shadow-ai-detection.md` (Reporter decoupling and Red Team hardening)

## By Pattern

- `[fp-reduction]` → `fix-fp-reduction-and-context-intelligence.md`
- `[multilingual-config]` → `fix-fp-reduction-and-context-intelligence.md`
- `[least-privilege]` → `feat-agent-least-privilege-audit.md`
- `[mcp-security]` → `feat-agent-least-privilege-audit.md`
- `[plugin-architecture]` → `feat-shadow-ai-detection.md`
- `[red-team-hardening]` → `feat-shadow-ai-detection.md`

## By Decision

- `[multilingual-keywords]` → Loaded dynamically from JSON with fallbacks (`fix-fp-reduction-and-context-intelligence.md`)
- `[regex-negative-lookbehinds]` → Distinguish script files from commands (`fix-fp-reduction-and-context-intelligence.md`)
- `[mcp-json-fallback]` → Line-based scanning fallback on JSON decode failures (`feat-agent-least-privilege-audit.md`)
- `[client-side-api-key-detection]` → Front-end key detection restricted to client paths/extensions to prevent backend false positives (`feat-agent-least-privilege-audit.md`)
- `[plugin-decoupling]` → Scanners and Reporters abstracted to base classes (`feat-shadow-ai-detection.md`)
