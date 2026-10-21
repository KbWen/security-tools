Branch: fix/skill-frontmatter-and-ci
Classification: quick-win
Classified by: Gemini 4 Argon (Medium)
Frozen: true
Created Date: 2026-10-21
Owner: KbWen
Mode: autopilot
Guardrails Mode: Quick
Recommended Skills: systematic-debugging (root-cause CI test failure), verification-before-completion (verify CI, validate scripts, and release gates)

## Session Info
- Agent: Gemini 4 Argon (Medium) + Flash Implementation Subagent (`8341bc74-2886-476f-bab4-07f14e22e246`) + Independent Pre-Commit Reviewer Subagent (`a1ab0300-99fa-42ee-aa21-04aaf2d9489f`)
- Session: 2026-10-21T10:35:00+08:00
- Platform: Antigravity

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO

## Pre-Implementation Checklist
- [x] Read project governance docs (`AGENTS.md`, `.agent/rules/engineering_guardrails.md`, `.agent/workflows/bootstrap.md`, `.agentcortex/context/current_state.md`)
- [x] Read relevant existing code (`.agents/skills/*/SKILL.md`, `.agent/skills/*`, `src/ghostcheck/checks/hallucination.py`, `tests/test_harden_resilience.py`, `tests/test_v1_0_0_presets.py`)

## Plan
- Mode: Fast Lane
- Ref: `AGENTS.md`, `.agent/rules/engineering_guardrails.md`, `docs/specs/_product-backlog.md`
- Target Files:
  1. `.agents/skills/api-design/SKILL.md`
  2. `.agents/skills/auth-security/SKILL.md`
  3. `.agents/skills/database-design/SKILL.md`
  4. `.agents/skills/frontend-patterns/SKILL.md`
  5. `.agents/skills/red-team-adversarial/SKILL.md`
  6. `src/ghostcheck/checks/hallucination.py`
  7. `tests/test_harden_resilience.py`
  8. `tests/test_v1_0_0_presets.py`
  9. `pyproject.toml`, `src/ghostcheck/__init__.py`, `uv.lock`, `README.md`, `README_zh-TW.md`, `docs/specs/_product-backlog.md`

## Risks (from /plan)
- [Mixed EOL in edited files]: Editing markdown/python files on Windows can introduce mixed CRLF/LF endings and fail `check_text_integrity.py`. Mitigation: Normalize line endings consistently and run `.agentcortex/bin/validate.ps1` + `python .agentcortex/tools/check_text_integrity.py --root . --baseline .agentcortex/tools/text_integrity_baseline.txt`.
- [Global urllib opener side effects]: Mocking `urllib.request.urlopen` vs `install_opener` across tests could break `test_hallucination_proxy_setup`. Mitigation: Keep `urllib.request.install_opener(opener)` when `proxy` or `not ssl_verify` is passed, reset with `urllib.request.install_opener(None)` when default, and mock `install_opener` in `test_proxy_propagation`.

## Review (`/review`)
- Independence: `isolated-subagent invoke_subagent` (Executor: `a1ab0300-99fa-42ee-aa21-04aaf2d9489f`)
- Security Verdict: PASS
- Red Team Verdict: Exempt (`quick-win`)
- Ready to commit?: Yes

## Test Evidence (`/test`)
- Test Files: `tests/test_harden_resilience.py`, `tests/test_v1_0_0_presets.py` (full suite: `tests/`)
- Command: `python -m pytest tests/ -v` -> `409 passed in 29.42s` (exit code 0)
- Command: `uv lock --check` -> `Resolved 22 packages in 2ms` (exit code 0)
- Command: `powershell -ExecutionPolicy Bypass -File .agentcortex/bin/validate.ps1` -> `Text integrity check passed (2 baseline exception(s) tracked). AgentCortex integrity check passed` (exit code 0)
- Command: `python -m ghostcheck.cli scan .` -> `Project Security Grade: A (100/100)` (exit code 0)

## Lessons
- `[Global-Opener-Isolation]`: Never leave `urllib.request.install_opener()` side effects active when instantiating default network checkers (`proxy=None, ssl_verify=True`); reset with `urllib.request.install_opener(None)` and mock `install_opener` in proxy unit tests to prevent cross-test CI pollution.
- `[Skill-Frontmatter-Parity]`: All `.agents/skills/*/SKILL.md` files must begin at line 1 with valid `---` YAML frontmatter (`name`, `description`) before any HTML scaffold comments, otherwise IDE skill loaders attempt to parse Markdown table delimiters (`|---|---|`) as YAML frontmatter.

## Resume
- State: SHIPPED
- Completed: Bootstrap, Plan, Flash Subagent Implementation (`8341bc74-2886-476f-bab4-07f14e22e246`), Independent Pre-Commit Review (`a1ab0300-99fa-42ee-aa21-04aaf2d9489f`), Test Verification, Ship & Archival
- Next: Push branch, open PR, verify GitHub Actions CI green, merge PR, tag and release `v1.2.14`
- Context: Fixed Antigravity IDE skill frontmatter load errors across `.agents/skills/*/SKILL.md` and resolved CI failure in `test_preset_scan_filtering` caused by global `urllib.request._opener` pollution from `test_proxy_propagation`.
- Handoff Reference: `ship:[doc=docs/specs/_product-backlog.md][code=src/ghostcheck/checks/hallucination.py][log=.agentcortex/context/archive/work/ship-v1.2.14-skill-frontmatter-and-ci-fix-2026-10-21.md]`
