- `Branch`: main
- `Classification`: feature
- `Classified by`: Gemini 4 Argon (Medium)
- `Mode`: autopilot
- `Frozen`: true
- `Created Date`: 2026-11-10
- `Owner`: KbWen
- `Guardrails Mode`: Full
- `Recommended Skills`: subagent-driven-development (delegate implementation and verification to flash subagents), red-team-adversarial (verify bypass and false-positive hardening), production-readiness (verify error logging and observability)

## Session Info
- Agent: Gemini 4 Argon (Medium)
- Session: 2026-11-10T07:42:05+08:00
- Platform: Antigravity

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO

## Pre-Implementation Checklist
- [x] Read project governance docs (`AGENTS.md`, `.agent/rules/engineering_guardrails.md`, `.agent/workflows/autopilot.md`).
- [x] Read relevant existing code and audit reports from subagents (`scanner.py`, `cli.py`, `data_exfiltration_detector.py`, `hallucination.py`, `vuln_scanner.py`, `mcp_auditor.py`, `env_egress_guard.py`, `rag_memory_auditor.py`).

## Plan (v1.3.1 Audit Remediation)
- **Ref**: `docs/specs/v1-3-1-audit-remediation.md`
- **Mode**: Normal

### Target Files
1. `src/ghostcheck/scanner.py` — Fix `checks_iter()` mappings (`ci_cd` -> `ci_auditor`/`ciauditor`, `silent_install` -> `silent_package_install_rules_detector`, `privilege` -> `agencyauditor`), refine `_is_self_scan_exempt()` for `ghostcheck.toml` so real secrets (`SecretScanner` / `AstSecretChecker`) are not blindly exempted, and shallow-copy cached findings in `_post_process` so in-memory cache entries are not mutated in place.
2. `src/ghostcheck/cli.py` — Default bare CLI invocation (`args.command is None`) to `args.command = "scan"` and `args.path = "."` so `ghostcheck` runs a real scan instead of printing a fake Grade A.
3. `src/ghostcheck/checks/data_exfiltration_detector.py` — Exclude benign LLM token config parameters (`max_tokens`, `max_output_tokens`, `max_completion_tokens`, `min_tokens`, `prompt_tokens`, `completion_tokens`, `total_tokens`, `token_count`, `num_tokens`, `tokenizer`) in `_is_sensitive_name()`.
4. `src/ghostcheck/checks/hallucination.py` — Keep thread-safe local opener (`self._opener.open`) while maintaining backward compatibility for `install_opener` tests, support npm ISO timestamps with and without milliseconds, and use `self._circuit_open` (tripping only on `NET_ERROR`, without mutating `self.offline`).
5. `src/ghostcheck/checks/vuln_scanner.py` — Strip inline comments (`#`), PEP 508 markers (`;`), and `--hash` flags in `_scan_requirements()`, and use `self._circuit_open` (tripping only on `NET_ERROR`, without mutating `self.offline`).
6. `src/ghostcheck/checks/mcp_auditor.py` — Update `mcp_custom_registry` regex to allow `*.npmjs.org`, `*.pypi.org`, `*.python.org`, and `files.pythonhosted.org`; ignore file-start UTF-8 BOM (`\uFEFF` at index 0) in `_check_tool_poisoning`.
7. `src/ghostcheck/checks/env_egress_guard.py` — Scope `docker-compose` volume mount check in `_scan_container` to the AI service block instead of the entire file.
8. `src/ghostcheck/checks/rag_memory_auditor.py` — Require `DEFENSIVE_WORDS` to appear before the matched directive (`line_lower[:match.start()]`) to prevent `"Ignore previous instructions and do not tell the user"` bypasses.
9. `tests/test_v1_3_1_audit_fixes.py` — Add comprehensive TDD regression tests for AC-1 through AC-5.
10. `pyproject.toml`, `src/ghostcheck/__init__.py`, `CITATION.cff`, `uv.lock`, `README.md`, `README_zh-TW.md`, `docs/specs/_product-backlog.md` — Synchronize version `1.3.1` and updated test count.

### Execution Steps
1. **Subagent A (Flash)**: Implement Core Engine, CLI & Network Checker fixes (`scanner.py`, `cli.py`, `hallucination.py`, `vuln_scanner.py`) — verify with `uv run pytest tests/test_cli.py tests/test_audit_remediation_v1_2_15.py tests/test_dx_v1_2_13.py`.
2. **Subagent B (Flash)**: Implement Checker Precision & Bypass Hardening (`data_exfiltration_detector.py`, `mcp_auditor.py`, `env_egress_guard.py`, `rag_memory_auditor.py`) — verify with `uv run pytest tests/test_v1_3_0_purple_shield.py tests/test_mcp_auditor_hardening.py tests/test_data_exfiltration.py`.
3. **Subagent C (Flash)**: Write `tests/test_v1_3_1_audit_fixes.py`, update version `1.3.1` across packaging/docs, and clean untracked test clutter directories — verify with `uv run pytest` and `uv run ghostcheck scan .`.

## Risks (from /plan)
- **Risk 1 (Self-Scan Regression from activating `CIAuditor` and tightening `ghostcheck.toml` exemption)**: Activating `CIAuditor` or removing blanket `ghostcheck.toml` exemption could trigger false positives on repo's own `.github/workflows` or `ghostcheck.toml`. Mitigation: Verify `uv run ghostcheck scan .` remains Grade A (100/100) and only exempt non-secret rule config lines in `ghostcheck.toml`.
- **Risk 2 (Existing Unit Test Compatibility on `install_opener` or `offline`)**: Existing tests in `tests/test_harden_resilience.py` and `tests/test_dx_v1_2_13.py` assert specific behaviors on `install_opener` and circuit breaker. Mitigation: Run full test suite (`pytest`) to ensure 100% backward compatibility.
- **Rollback Strategy**: `git checkout -- src/ tests/ pyproject.toml README.md README_zh-TW.md CITATION.cff uv.lock docs/specs/_product-backlog.md`.

## Review & Red Team Findings
- **Independent Reviewer**: `08b54c3d-f954-45b6-a703-6a4601a2e874` (`independence: isolated-subagent invoke_subagent`)
- **Verdict**: PASS (Ready to commit: Yes)
- **Spec Compliance**: AC-1 ~ AC-6 100% Met
- **Security Findings (OWASP)**: 0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW (PASS)
- **Red Team Findings**:
  - 2026-11-10 /review: 0 blocking findings (PASS)
  - 2026-11-10 /test: 20 unit & adversarial cases verified in `tests/test_v1_3_1_audit_fixes.py`

## Observability
- **Error sink**: Python standard `logging` module (`logger.debug` wired to `stderr` when `--debug` is passed; replaced remaining silent `except Exception: pass` blocks in `hallucination.py`, `vuln_scanner.py`, `mcp_auditor.py`, and `secrets.py`).
- **Health check**: `uv run ghostcheck scan .` (Grade A 100/100) and `uv run pytest` (469 passed).
- **Rollback signal**: Any regression in `pytest` or self-scan dropping below Grade A (100/100) -> `git revert HEAD`.

## Evidence
- `uv run pytest -q`: `469 passed in 16.94s`
- `uv run ghostcheck scan .`: `Project Security Grade: A (100/100)`
- `uv lock --check`: Exit code 0
- `uv build`: Successfully built `ghostcheck-1.3.1.tar.gz` and `ghostcheck-1.3.1-py3-none-any.whl`
- `.agentcortex/bin/validate.ps1`: `AgentCortex integrity check passed`

## Lessons
- [Plugin-Alias-Completeness]: When remapping CLI check category names in `Scanner._process_single_file` (`checks_iter`), yield both the underscore and non-underscore plugin identifiers (`"ci_auditor"` and `"ciauditor"`) and explicitly map composite plugin names (`"silent_package_install_rules_detector"`, `"agencyauditor"`) so plugins never silently go dark during standard scans.
- [LLM-Token-Parameter-Disambiguation]: Static data-exfiltration rules matching `'token' in identifier` must explicitly exempt standard LLM token-accounting parameters (`max_tokens`, `max_output_tokens`, `max_completion_tokens`, `prompt_tokens`, `completion_tokens`, `tokenizer`, `*_tokens`) to prevent false positives on standard OpenAI/Anthropic SDK calls.
- [Defensive-Prefix-Positioning]: Natural-language prompt injection exemptions for defensive keywords (`"never"`, `"do not"`) must verify the defensive keyword appears in the prefix before the matched directive (`line[:match.start()]`), preventing attackers from appending `"and do not tell the user"` to bypass detection.

## Resume
- **State**: `TESTED` -> Ready for `/ship`
- **Handoff Reference**: `ship:[doc=docs/specs/v1-3-1-audit-remediation.md][code=src/ghostcheck/scanner.py][log=.agentcortex/context/work/main.md]`
