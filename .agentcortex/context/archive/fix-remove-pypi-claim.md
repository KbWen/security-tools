# Work Log: fix-remove-pypi-claim

- Branch: fix/remove-pypi-claim
- Classification: quick-win
- Classified by: Gemini 3.8 Flash
- Frozen: true
- Created Date: 2026-10-12
- Owner: wen
- Guardrails Mode: Quick
- Recommended Skills: writing-plans, verification-before-completion

## Session Info
- Agent: Gemini 3.8 Flash
- Session: 2026-10-12T23:30:00+08:00
- Platform: Antigravity

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO

## Task Scope
1. Documentation & claim updates:
   - Remove `pip install ghostcheck` PyPI claim from README.md and README_zh-TW.md.
   - Establish GitHub source / direct install as primary standard installation option.
   - Update docs/specs/ references if necessary.
2. Code & template updates:
   - In `src/ghostcheck/init.py`, update CI generation templates (GitHub Actions & GitLab CI) so they don't attempt `pip install ghostcheck` from PyPI.
3. Metadata cleanup:
   - In `pyproject.toml`, update placeholder email `kbwen@example.com` or clean up packaging metadata.
4. Verification & Testing:
   - Run tests to ensure no regressions in CLI / CI generator.
   - Run lint/syntax checks.

## Plan Reference
- Plan: Remove PyPI Installation Claim and Switch to GitHub Direct Install (Option B)
- Mode: Normal
- Status: TESTED

## Risks (from /plan)
- [Risk 1 - Outdated CI Template]: Existing or generated CI templates failing due to attempting PyPI install.
  - Mitigation: Update GitHub Actions and GitLab CI generator in `src/ghostcheck/init.py` to install from GitHub repository (`pip install git+https://github.com/KbWen/security-tools.git`).
- [Risk 2 - Packaging metadata mismatch]: Author email change or lockfile desync in `pyproject.toml`.
  - Mitigation: Update author email to verified committer email (`luvseldom@hotmail.com`) and run `uv lock --check` / test suite.

## Evidence
- Baseline: 368/368 tests passed in 25.36s.
- Post-Implementation: 368/368 tests passed in 20.14s (0 failures).
- Unit tests: Enhanced `test_cli_init_ci` in `tests/test_cli.py` to assert GitHub workflow and GitLab CI template content; verified git install present and bare `pip install ghostcheck` absent.
- GitLab CI Hardening: Implemented Tenth Man finding by adding `apt-get update && apt-get install -y --no-install-recommends git` to Debian slim image script.
- Metadata & Lockfile: `pyproject.toml` author email updated to `luvseldom@hotmail.com`; `uv lock --check` passed in 18ms.
- Self-Scan: `ghostcheck scan .` achieved Grade A (100/100) with 0 CRITICAL/HIGH/MEDIUM/LOW findings.
- Repository Integrity: `.agentcortex/bin/validate.ps1` passed text and AgentCortex integrity checks.

## Review & Test Verdicts
- `/review` Status: PASS (Five-Perspective Expert Roundtable unanimous PASS; Tenth Man GitLab CI git dependency finding resolved)
- `/test` Status: PASS (368/368 passed in 20.14s)

## Resume
- Option B completed: All PyPI installation claims removed, documentation updated to GitHub release tag direct install, version badge updated to 1.2.9, CI generator templates secured, and author email cleaned.
