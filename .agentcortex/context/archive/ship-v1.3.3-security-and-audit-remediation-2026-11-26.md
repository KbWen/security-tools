# Work Log (Archived): v1.3.3 Security Hardening & Core Audit Remediation

- **Branch**: main
- **Classification**: feature
- **Classified by**: Antigravity (Gemini 4 Neon)
- **Frozen**: true
- **Created Date**: 2026-11-26
- **Shipped Date**: 2026-11-26
- **Owner**: wen
- **Guardrails Mode**: Full
- **Spec**: `docs/specs/v1-3-3-security-and-audit-remediation.md` (`status: frozen`)

## Session Info
- Agent: Gemini 4 Neon (High) + low-tier `flash` implementation/test subagents (`fb2b95a3-462e-4b03-901a-eea6b4a4accd`, `c694eaef-f43a-43f2-be27-dd033e6bc488`, `e1442f59-5e01-471c-82e8-91d0235998bc`, `8afc3cb5-8054-408e-a674-5a5547c49504`, `923cd0a2-d384-4d65-a22d-ed7b4e760fef`, `6ad5d254-9945-4c4d-b5af-3aedaa1d941a`)
- Independent Reviewer: `bb74aee3-94fe-4131-a418-b09609aee309` (`independence: isolated-subagent invoke_subagent`)
- Session: 2026-11-26T16:30:35+08:00
- Platform: Antigravity

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO

## Review
- **Round 1** (`bb74aee3-94fe-4131-a418-b09609aee309`): `Security Verdict: NOT READY` (1 blocking HIGH `SEC-01`, 2 MEDIUM `SEC-02`/`SEC-03`, 2 Red Team MEDIUM, 5 LOW polish).
- **Round 2** (`bb74aee3-94fe-4131-a418-b09609aee309`): All Round-1 findings closed & verified with 9 additional regression tests (`516 passed`).
  - `Security Verdict: PASS` (0 CRITICAL, 0 HIGH, 0 MEDIUM)
  - `Red Team Verdict: PASS WITH NOTES` (0 CRITICAL, 0 HIGH, 0 MEDIUM, 4 LOW advisory)
  - `Ready to commit?: Yes`

## Security Findings
- `SEC-01` [HIGH — Resolved]: Plaintext secret leakage via pre-populated `context`, multi-secret GPA-06/07 lines, and cache-hit sibling context — fixed in `scanner.py:979-1005,1128-1164` and `privilege_auditor.py:240,263,288-299`.
- `SEC-02` [MEDIUM — Resolved]: `SecretValidator` third-party `sk-` leakage & non-ASCII `UnicodeEncodeError` — fixed in `secret_validator.py:23-44,63`.
- `SEC-03` [MEDIUM — Resolved]: Git subprocess PATH relative/symlink checks, `-c core.fsmonitor=false`, and `AIMarker` `_safe_git_env()` — fixed in `git_diff_scanner.py` and `ai_marker.py`.
- Unresolved CRITICAL/HIGH findings: `0`.

## Red Team Findings
- 2026-11-26 /review (Round 1): 1 HIGH (`SEC-01`), 2 MEDIUM (`SecretValidator` non-ASCII, `MCPAuditor` `::0` / userinfo `@`), 5 LOW — all remediated in Round 2.
- 2026-11-26 /review (Round 2): 0 CRITICAL, 0 HIGH, 0 MEDIUM, 4 LOW advisory notes.
- 2026-11-26 /test: 37 new TDD & adversarial regression test cases added in `tests/test_v1_3_3_security_remediation.py`.

## Observability
- **Error Sink**: Python `logging.getLogger(__name__)` (`logger.debug` in `plugin_manager.py`, `plugins/loader.py`, `git_diff_scanner.py`, `ai_marker.py`, `hallucination.py`, `secret_validator.py`, routed to `stderr` when `--debug` is enabled in `cli.py:224`).
- **Health / Verification Signals**: `pytest -q` (`516 passed in 32.77s`), `ghostcheck scan . --offline` (`Grade A 100/100`), `uv lock --check` (exit 0), `uv build` (wheel + sdist), `.agentcortex/bin/validate.ps1` (PASS).
- **Rollback Signal & Procedure**: If a regression surfaces in downstream scans (unexpected FPs, CLI crash, or cache error), detect via CI exit code / `--debug` stderr logs and revert via `git revert <release-commit>` and delete tag `v1.3.3` if unpublished, or cut patch `v1.3.4`.

## Lessons
- `[Private-Field-Output-Strip]`: Strip internal `_raw_value` at `Scanner._post_process()` exit, disk cache persistence, JSON reporter, and baseline export, and redact pre-populated & sibling-secret line contexts unconditionally before stripping `_raw_value` so cache hits never re-read unmasked lines.
- `[Instance-Opener-Isolation]`: Bind proxy/TLS handlers (`handlers.append(...)` before `build_opener`) to an instance `self.opener` and never call process-global `urllib.request.install_opener()`.
- `[Commonpath-Binary-Guard]`: Validate both PATH directories (`os.path.isabs`) and resolved binary candidates with `os.path.commonpath(normcase(realpath(...)))` to block repository subdirectory/symlink hijacking, paired with explicit `timeout` and `GIT_CONFIG*` env stripping.

## Resume
- Wave 1 (v1.3.3) shipped cleanly; Wave 2 deferred audit items are tracked in `docs/specs/_product-backlog.md` under **Epic 11 (v1.3.4)**.
- `ship:[doc=docs/specs/v1-3-3-security-and-audit-remediation.md][code=src/ghostcheck/scanner.py][log=.agentcortex/context/archive/ship-v1.3.3-security-and-audit-remediation-2026-11-26.md]`
