---
title: "GhostCheck v1.3.3 — Security Hardening, Secret Leakage Remediation & Core Engine Audit Fixes"
status: frozen
version: "1.3.3"
created: "2026-11-26"
updated: "2026-11-26"
---

# Specification: GhostCheck v1.3.3 Security Hardening, Secret Leakage Remediation & Core Engine Audit Fixes

## 1. Overview & Problem Statement

A comprehensive multi-module read-only audit of GhostCheck v1.3.2 (commit `5a55a95`) uncovered high-priority security vulnerabilities, plaintext secret leakage vectors, broken core engine wiring, and high-severity false positives/negatives. This specification scopes the **Wave 1 (v1.3.3)** remediation of the highest-impact security and reliability defects, while deferring lower-priority / broader refactors to the **Wave 2 (v1.3.4)** backlog in `docs/specs/_product-backlog.md`.

### Root Causes Targeted in v1.3.3

1. **Plaintext `_raw_value` Leakage (`scanner.py`, `json_reporter.py`, `cli.py`)**: Scanners attach `_raw_value` for internal validation, but `Scanner._post_process()` never removes it before returning findings, and `Scanner.scan()` persists raw findings into `~/.ghostcheck/cache/results_cache.json`. Consequently, `--format json`, `ghostcheck baseline create` (`.ghostcheck-baseline.json`), and disk caches leak full plaintext credentials.
2. **Unmasked Context Leakage (`privilege_auditor.py`, `scanner.py`, `html_reporter.py`, `console.py`)**: `PrivilegeAuditor` GPA-06 (`api_key_command_arg`) writes raw `line.strip()` into `context` without masking; `Scanner._post_process()` leaves AST-concatenated secret lines unmasked when reconstructed `_raw_value` is not verbatim in the raw line; non-string `_raw_value` can crash reporter masking (`raw_val[:4]`).
3. **HTML Report XSS & SARIF 2.1.0 Non-Compliance (`html_reporter.py`, `sarif_reporter.py`)**: `HTMLReporter` interpolates `severity` and `grade` without `html.escape()`; `SarifReporter` emits invalid `"startLine": 0` for repo/file-level findings and omits `rule_name` fallback (affecting `DockerRiskChecker`).
4. **`SecretValidator` Dead Wiring & Cross-Provider Token Leakage (`scanner.py`, `secret_validator.py`)**: `scanner.py:997` checks `'secret'`/`'token'` in `fnd_id`, missing `"OpenAI API Key"`; `secret_validator.py:28` sends any `sk-` token (including Anthropic `sk-ant-...` and OpenRouter `sk-or-...`) to `https://api.openai.com/v1/models`.
5. **Plugin Module Hijacking & Global Opener Mutation (`plugins/loader.py`, `hallucination.py`, `plugin_manager.py`)**: `PluginLoader` assigns arbitrary plugin filenames directly into `sys.modules[module_name]` and resolves local plugins from `os.getcwd()` instead of `project_root`; `HallucinationChecker` mutates global `urllib.request.install_opener()` instead of using instance `self.opener.open()`, and crashes on `upload_time: None`; `PluginManager` has a silent `except Exception: pass`.
6. **Git Binary Subdirectory Hijack & Missing Subprocess Timeout (`git_diff_scanner.py`, `ai_marker.py`)**: `_get_secure_git()` uses raw string prefix and exact-equality checks, failing to block `<project_root>/bin/git` on `PATH`; `GitDiffScanner` lacks `timeout=` and leaves `GIT_CONFIG*` env vars intact.
7. **Core Wiring, Inline Suppression & Cache Concurrency (`scanner.py`, `context_auditor.py`)**: `Scanner.__init__` omits `config` when instantiating plugins (`ShadowAIDetector`, `EnvEgressGuard`); inline `ghostcheck-ignore` fails when plugins pre-populate truncated `context`, is case-sensitive on the pre-check, and lacks word-boundary before `rem`; `results_cache.json` temp file lacks `threading.get_ident()`; `ContextAuditor._has_keyword` raises `IndexError` on `""`.
8. **High-Impact Checker Precision & Dead-Code Bugs (`mcp_auditor.py`, `env_scanner.py`, `privilege_auditor.py`, `rag_memory_auditor.py`, `iac_scanner.py`)**:
   - `MCPAuditor`: IPv6 loopback `::1` / `[::1]` falsely flagged as CRITICAL `mcp_insecure_binding`; `--api` / `--uri` falsely flagged as HIGH `mcp_custom_registry`.
   - `EnvScanner`: `\s*` with `re.DOTALL` swallows next line after empty `FOO=`.
   - `PrivilegeAuditor`: `"..."` ellipsis triggers `".."` check in `is_overly_broad_path` (CRITICAL `mcp_root_mount` FP).
   - `RagMemoryAuditor`: ROT13 typo `"qvferneq"` misses `"disregard"` (`"qvfertneq"`).
   - `IaCScanner`: `scan()` skips `.tfstate` files, making `.tfstate` detection dead code.

## 2. Acceptance Criteria (AC)

- **AC-1 (Zero Plaintext Secret Leakage Across Reports, Baselines, and Cache)**:
  - `Scanner._post_process()` MUST strip `_raw_value` (after `SecretValidator` and `SeverityEngine` have run) from all returned findings.
  - `Scanner._save_results_cache()` / `Scanner.scan()` MUST NOT persist `_raw_value` to `~/.ghostcheck/cache/results_cache.json`.
  - `JsonReporter.report()` and `cli.py` `baseline create` MUST defensively strip private `_`-prefixed keys (such as `_raw_value`) before serializing JSON.
  - `PrivilegeAuditor` GPA-06 (`api_key_command_arg`) MUST mask matched API keys in `context` identically to GPA-07.
  - `Scanner._post_process()` dynamic context builder MUST mask AST-concatenated findings safely (falling back to masked `value_preview` if `raw_val` is not verbatim in the line so raw fragments are not leaked), and `HTMLReporter`/`ConsoleReporter` MUST guard `str(raw_val)` against non-string values.
- **AC-2 (HTML Report XSS Prevention & SARIF 2.1.0 Compliance)**:
  - `HTMLReporter.report()` MUST `html.escape()` `severity` (`sev`), `grade`, and `score_val`, and restrict CSS grade class suffix to valid grade characters (`A`/`B`/`C`/`D`/`F`).
  - `HTMLReporter` and `SarifReporter` MUST resolve `rule_name` as fallback for finding title / `ruleId`.
  - `SarifReporter._get_results()` MUST guarantee `region.startLine >= 1` (`max(1, int(f.get('line') or 1))`).
- **AC-3 (`SecretValidator` Wiring & Provider Isolation)**:
  - `Scanner._post_process()` MUST invoke `self.secret_validator.validate(fnd)` for API key findings (`'secret'`, `'token'`, `'key'`, `'openai'` in `fnd_id.lower()`) when enabled (`validate_secrets=True` and `not offline`).
  - `SecretValidator.validate()` MUST check `finding.get('name') or finding.get('pattern_name') or ''` and MUST NOT send non-OpenAI `sk-` keys (`sk-ant-...`, `sk-or-...`, `sk_live_...`, etc.) to `api.openai.com`.
- **AC-4 (Plugin Isolation, Instance Opener & PyPI Metadata Resilience)**:
  - `PluginLoader._load_from_file()` MUST register loaded plugins under a namespaced `sys.modules` key (`ghostcheck_user_plugin_<safe_name>_<hash>`) so plugins cannot clobber stdlib or `ghostcheck` modules; `PluginLoader.__init__` MUST accept `project_root` (defaulting to `os.getcwd()`) and `Scanner` MUST pass `self.project_root`.
  - `HallucinationChecker` MUST use `self.opener.open(...)` for PyPI/npm/crates requests and MUST NOT mutate global `urllib.request.install_opener(...)`; `_check_pypi_online_status` MUST ignore `None` `upload_time` values before calling `min()`.
  - `PluginManager._load_from_package()` MUST log exceptions with `logger.debug(...)` instead of silent `pass`.
- **AC-5 (Secure Git Binary Resolution & Subprocess Hardening)**:
  - `_get_secure_git()` in `GitDiffScanner` and `AIMarker` MUST use `os.path.normcase(os.path.realpath(...))` + `os.path.commonpath` to block `git` binaries in `cwd`, `project_root`, and any subdirectory thereof, and on Windows check executable extensions (`.exe`, `.cmd`, `.bat`) before extensionless files.
  - All `subprocess.run()` calls in `GitDiffScanner` MUST set `timeout=15` and strip `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `GIT_CONFIG` from `safe_env`.
- **AC-6 (Core Wiring, Inline Suppression & Cache Concurrency)**:
  - `Scanner.__init__` MUST inject `config=self.config` into plugins whose `__init__` declares a `config` parameter (`ShadowAIDetector`, `EnvEgressGuard`).
  - Inline `ghostcheck-ignore` parsing in `Scanner._post_process()` MUST inspect the full source line (from `file_content_cache` when `file_path` and `line > 0` exist) in addition to `ctx_str`, match case-insensitively, require `\brem\b` for batch comments, and preserve untrusted-asset strict rule-ID targeting.
  - `Scanner._save_results_cache()` MUST use `f".tmp.{os.getpid()}.{threading.get_ident()}"` for atomic writes.
  - `ContextAuditor._has_keyword()` MUST return `False` for empty/whitespace-only keywords without raising `IndexError`.
- **AC-7 (High-Impact Checker Precision & Dead-Code Remediation)**:
  - `MCPAuditor._is_insecure_binding()` MUST NOT flag IPv6 loopback (`::1`, `[::1]`, `[::1]:8000`) or non-wildcard IPv6 addresses (`fe80::1`) while continuing to flag `0.0.0.0`, `::`, `[::]`, `0:0:0:0:0:0:0:0`, `::ffff:0.0.0.0` (with or without `:port`).
  - `MCPAuditor` `mcp_custom_registry` regex MUST require a boundary before `-i` so flags like `--api` or `--uri` are not falsely flagged.
  - `EnvScanner` regex MUST use `[ \t]*` instead of `\s*` around `=` so empty variables (`FOO=\nDEBUG=true`) never swallow subsequent lines.
  - `PrivilegeAuditor.is_overly_broad_path()` MUST only flag `..` as a path traversal segment (`..`, `../`, `/..`), NOT ellipses (`"..."`) in prose/descriptions.
  - `RagMemoryAuditor` MUST fix ROT13 canonical string `"qvferneq nyy cerivbhf"` -> `"qvfertneq nyy cerivbhf"`.
  - `IaCScanner.scan()` MUST dispatch `.tfstate` files to `scan_file()`.
- **AC-8 (Backlog Deferral, Regression Tests & v1.3.3 Release Sync)**:
  - Record all deferred Wave 2 (v1.3.4) audit items in `docs/specs/_product-backlog.md`.
  - Add dedicated TDD & adversarial regression test suite in `tests/test_v1_3_3_security_remediation.py` covering AC-1 through AC-7, and update the 2 opener-isolation unit tests in `tests/test_harden_resilience.py`.
  - Synchronize version `1.3.3` and test count across `pyproject.toml`, `src/ghostcheck/__init__.py`, `src/ghostcheck/checks/hallucination.py`, `CITATION.cff`, `uv.lock`, `README.md`, `README_zh-TW.md`, and `docs/specs/_product-backlog.md`.
  - All pytest tests pass, offline self-scan achieves `Grade A (100/100)`, `uv lock --check` passes, and wheel/sdist build succeeds.

## 3. Non-Goals (Deferred to v1.3.4 Backlog)

- Rewriting `SilentInstaller` parser/AST recursion, `AISupplyChainScanner` multiline MCP JSON regex, `DockerRiskChecker` multiline `ENV` parser, `EnvEgressGuard` Dockerfile egress, `CIAuditor`/`IaCScanner`/`FirebaseRulesAuditor` `re.DOTALL` rewrites, `DataExfiltrationDetector` literal taint overhaul, `MultimodalPolyglotScanner` SVG fallback inheritance/tail, `Config` `enabled_checks` override semantics, `AIMarker` repo-level cache split, `LethalTrifectaDetector` `WARNING` severity refactor, and `AstSecretChecker` `.join()` separator — all tracked explicitly in `docs/specs/_product-backlog.md` for Wave 2 (v1.3.4).
- Adding any third-party runtime dependencies.
- Modifying any existing `[Frozen]` historical specifications.
