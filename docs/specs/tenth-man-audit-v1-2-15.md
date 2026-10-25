---
title: "GhostCheck v1.2.15 — Tenth-Man Deep Audit & Concurrency Hardening"
status: frozen
version: "1.2.15"
created: "2026-10-25"
updated: "2026-10-25"
---

# Specification: GhostCheck v1.2.15 Tenth-Man Deep Audit & Concurrency Hardening

## 1. Overview & Problem Statement

A Tenth-Man adversarial code review of GhostCheck v1.2.14 identified 8 concrete functional and resilience defects across caching, CLI flags, baseline path resolution, configuration wiring, multi-threaded scanner state, Windows path matching, and preset completeness:

1. **Results Cache Poisoning (`results_cache.json`)**: `Scanner._load_results_cache` and `Scanner._save_results_cache` only include `preset` and `enabled_checks` in the integrity metadata hash, omitting `offline`, `version`, and `disabled_rules`. Running `ghostcheck scan . --offline` caches empty dependency findings and causes subsequent online `ghostcheck scan .` runs to skip `HallucinationChecker` and `VulnScanner`.
2. **Baseline Default Filename Mismatch**: `ghostcheck baseline create` writes `.ghostcheck-baseline.json` by default (`cli.py`), whereas `Scanner.__init__` only auto-discovers `.ghostcheckbaseline` (`scanner.py`) and `IgnoreMatcher` only ignores `.ghostcheckbaseline` (`ignorefile.py`).
3. **Missing CLI Flags Advertised in Documentation (`init --hook`, `honeypot --clean`)**: Both `README.md` and `README_zh-TW.md` document `ghostcheck init --hook` and `ghostcheck honeypot --clean`, but neither flag exists in `cli.py`, `init.py`, or `honeypot.py`.
4. **Disconnected `exclude_patterns` Config & `.env*` Over-Exclusion**: `Scanner.__init__` never passes `config.get("exclude_patterns")` to `IgnoreMatcher`, rendering `exclude_patterns` in `ghostcheck.toml` a no-op; additionally, `init.py` and `ghostcheck.toml` include `".env*"` in `exclude_patterns`, which would blind `EnvScanner` instead of targeting `*.canary`.
5. **Hardcoded CWD in `GhostCheckConfig(".")`**: `cli.py` initializes `GhostCheckConfig(".")` instead of resolving from the target scan/honeypot `path`.
6. **ThreadPoolExecutor Race Conditions in `HallucinationChecker` and `VulnScanner`**: Both checkers share mutable instance state (`self._last_status`, `self.cache`) across `ThreadPoolExecutor` workers without locks or atomic file replacement (`os.replace`), risking corrupted cache files and cross-thread status clobbering.
7. **Windows Case-Sensitivity Mismatch in `IgnoreMatcher.is_ignored`**: `os.path.normcase(os.path.realpath(path))` lowercases `path_norm` on Windows while keeping `self.patterns` in original case, causing prefix checks (`path_norm.startswith(p)`) to fail on patterns with uppercase characters.
8. **Preset Module Gaps & `SecretValidator` Safety**: `next.js`, `flutter`, `django`, and `fastapi` presets in `PresetManager` omit `vuln`, `entropy`, and `tamper`; `SecretValidator` falls back to sending full `context` lines if `_raw_value` is absent and runs live network validation without explicit opt-in (`validate_secrets`).

## 2. Acceptance Criteria (AC)

- **AC-1 (Results Cache Metadata Isolation)**: `Scanner._load_results_cache` and `Scanner._save_results_cache` MUST include `offline`, `version`, `disabled_rules`, and `exclude_patterns` in the cache integrity metadata so switching `--offline` off or upgrading GhostCheck invalidates stale cache entries.
- **AC-2 (Baseline Auto-Discovery & Ignore Alignment)**: `Scanner.__init__` MUST auto-discover both `.ghostcheckbaseline` and `.ghostcheck-baseline.json`, and `IgnoreMatcher` MUST include `.ghostcheck-baseline.json` in `default_ignores`.
- **AC-3 (`ghostcheck init --hook` & `ghostcheck honeypot --clean`)**:
  - `ghostcheck init --hook` installs a pre-commit hook at `.git/hooks/pre-commit` running `ghostcheck scan --staged`.
  - `ghostcheck honeypot --clean [path]` removes deployed decoy canary files (`.env.canary`, `aws_credentials.canary`, `id_rsa.canary`) and cleans their entries from `.gitignore` and `.ghostcheckignore` without requiring `--url`.
- **AC-4 (`exclude_patterns` Wiring & `.env` Preservation)**: `Scanner.__init__` MUST pass `config.get("exclude_patterns")` to `IgnoreMatcher(patterns=...)` when `ignore_enabled=True`, and `init.py` / `ghostcheck.toml` MUST replace `".env*"` with `"*.canary"` so `.env` files are not silently ignored.
- **AC-5 (Target Path Config Resolution)**: `cli.py` MUST initialize `GhostCheckConfig` using the resolved target `path` argument (when provided) rather than hardcoded `"."`.
- **AC-6 (Thread-Safe Network Checkers & Atomic Cache Writes)**:
  - `HallucinationChecker` MUST eliminate shared mutable `self._last_status` across threads (return `(result, status)` tuples from `_check_*_online` helpers or use thread-safe local status) and protect `self.cache` / `_save_cache` with `threading.Lock()` and atomic temp-file `os.replace`.
  - `VulnScanner` MUST protect `self.cache` / `_save_cache` and `_consecutive_net_failures` with `threading.Lock()` and atomic temp-file `os.replace`.
- **AC-7 (Cross-Platform Case-Safe `IgnoreMatcher`)**: `IgnoreMatcher.is_ignored` MUST preserve original relative path casing for pattern matching while supporting case-insensitive matching on Windows (`os.name == 'nt'`) for prefix checks (`startswith`).
- **AC-8 (Preset Completeness, `SecretValidator` Opt-In & Docs Sync)**:
  - `PresetManager` presets (`next.js`, `flutter`, `django`, `fastapi`) MUST include `vuln`, `entropy`, and `tamper` (and `terraform` MUST include `entropy` and `tamper`).
  - `SecretValidator` MUST default to opt-in (`config.get("validate_secrets", False)`) in `Scanner.__init__` and only validate clean token strings (`_raw_value` without whitespace/newlines).
  - Version bumped to `1.2.15` across `pyproject.toml`, `src/ghostcheck/__init__.py`, `src/ghostcheck/checks/hallucination.py`, `uv.lock`, `README.md`, `README_zh-TW.md`, and `docs/specs/_product-backlog.md`.

## 3. Non-Goals

- Do NOT add `docker` or `hallucination` to the `terraform` preset (intentionally excluded per `tests/test_v1_0_0_presets.py`).
- Do NOT introduce new external runtime dependencies in `pyproject.toml`.
- Do NOT alter existing finding rule IDs or break backward compatibility with existing tests.
