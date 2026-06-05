---
description: Fully automated implementation session. AI assumes Project Owner role for all gate approvals.
---
# Autopilot Mode

> This workflow enables a Flash model to execute the full AgentCortex development lifecycle
> without human intervention. The AI assumes the Project Owner role and auto-approves all gates.

## Role Assignment

You are acting as **Project Owner (KbWen)**. You have full authority to:
- Approve all gate handshakes (bootstrap, plan, implement, review, ship)
- Respond "proceed" to all confirmation prompts
- Respond "yes" to all scope/escalation warnings
- Classify tasks and freeze classifications
- Approve all spec changes and plan modifications

## Auto-Approval Protocol (native, not string-matching)

This workflow activates **Auto-Mode** per `AGENTS.md` §Auto-Mode (Autopilot) Contract.
On entry, set `Mode: autopilot` in the active Work Log header. Under that contract the
Runtime v5 human-confirmation handshakes (§3 bootstrap, §6 plan, §8 implement) are
auto-satisfied **natively** — do NOT pattern-match prompt wording to self-respond.
Proceed through the phase sequence below without pausing for human confirmation.

**Red line (per the contract §3)**: Auto-Mode auto-approves ONLY human confirmations. It
does NOT relax any gate. `verdict=fail`, missing Evidence, a CRITICAL/HIGH Security
finding, a CRITICAL Red Team finding, or a Confidence Gate `<80%` STILL STOP the run —
fix and re-run the phase; never auto-approve past a real failure.

**Review independence (per the contract §4 + `review.md` §Auto-Mode Independence Rule)**:
The implementing agent MUST NOT *silently* self-grade. **Default** (no isolated-subagent
runtime configured — the common case on Antigravity 2.0 / Claude Code / Codex): the review is
a **marked clean-slate self-review** (re-derive from diff + spec alone, mark
`independence: degraded (self-review)`), and the ship output carries the
`⚠️ shipped without independent review` flag. **Only if** the operator configured a true
isolated reviewer (Antigravity `start_subagent` / Claude Code Agent-or-hook / Codex
`codex exec` / `/ask-openrouter`) is the review dispatched there and the flag suppressed.
"Ready to commit?" passes ONLY on the reviewer's explicit PASS; if it fails, fix and re-review.

## Task Brief

Implement **GhostCheck MVP** as specified in `docs/specs/ghostcheck-mvp.md`.

**GhostCheck** is a CLI security scanner for AI-assisted development workflows. It detects:
1. **Hallucinated packages** — dependencies that don't exist or are suspiciously new on PyPI/npm
2. **Leaked secrets** — API keys, tokens, passwords in AI chat logs and markdown files (with file-type-aware severity adjustment)
3. **Risky agent rules** — dangerous permissions in .agent/, .cursor/, and similar AI config files

Additional MVP features:
4. **Demo command** — `ghostcheck demo` generates sample vulnerable files, scans them, and cleans up
5. **Ignore file** — `.ghostcheckignore` support for excluding paths/patterns from scans
6. **Smart severity** — Severity adjusted by file context (example files downgraded, AI chat logs upgraded)

## Workflow Sequence

Execute IN ORDER, completing each phase fully before moving to the next:

1. **`/bootstrap`** — Classify as `feature`. Create work log. Reference spec: `docs/specs/ghostcheck-mvp.md`.
2. **`/plan`** — Produce implementation plan referencing the spec's Acceptance Criteria.
3. **`/implement`** — Create all source files, tests, fixtures, docs, CI config. Follow the architecture in the spec.
4. **`/review`** — per `review.md` §Auto-Mode Independence Rule (default: **marked clean-slate
   self-review** with the `⚠️` ship flag; a true isolated-subagent reviewer only if the
   operator configured one). Either way the review conducts multi-role review from FOUR perspectives:
   - 🔒 **Security Researcher**: Pattern accuracy, evasion coverage, API safety
   - 👨‍💻 **Python Developer**: Code quality, edge cases, error handling, CLI UX
   - 🌍 **Open Source Maintainer**: README clarity, install ease, test quality, Chinese docs
   - ⚙️ **DevOps Engineer**: CI pipeline, exit codes, JSON output, pip install
5. **`/test`** — Run `pytest tests/ -v --tb=short`. Capture evidence.
6. **`/ship`** — Commit with Conventional Commits format, update SSoT, archive work log.

## Language Rules

- All code, comments, CLI output, and primary documentation: **English**
- Create `docs/ghostcheck/README_zh-TW.md`: **繁體中文**
- Git commits: **English** (Conventional Commits format, e.g., `feat: add hallucination checker`)
- Work log and internal AgentCortex docs: **English**

## Key Technical Constraints

- **Python ≥3.9**, no external runtime dependencies (stdlib only)
- Dev dependencies: `pytest`, `pytest-cov` only
- CLI uses `argparse` (stdlib)
- HTTP: `urllib.request` (stdlib)
- Colors: ANSI escape codes (no external lib)
- File structure: `src/ghostcheck/` layout with pyproject.toml

## Success Criteria

The session is complete when:
1. All source files are created and functional (including `ignorefile.py` and `demo.py`)
2. All tests pass (`pytest` exit code 0)
3. Multi-role review has no ❌ failures
4. `ghostcheck scan .` runs successfully against the repo itself
5. `ghostcheck demo` runs and produces expected output
6. `.ghostcheckignore` is tested with both inclusion and exclusion patterns
7. Work log is archived and `current_state.md` is updated
8. Changes are committed and ready for push
