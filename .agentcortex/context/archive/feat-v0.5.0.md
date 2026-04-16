# Work Log: feat-v0.5.0
<!-- worklog-key: feat-v0.5.0 -->

## Session Info

- Owner: Flash
- Branch: feat/v0.5.0
- Session ID: flash-2026-03-21T12:30:00+08:00
- Platform: windows

## Task Classification

gate: bootstrap
classification: feature
verdict: pass
missing: []

## Context & Plan

The project is starting the **v0.5.0** phase. The goal is to implement multi-language AST scanning (specifically JS/TS), an Intelligent Severity Engine, and a deep scan for `.env` files. 

The previous session updated the framework to v5.3.0 and performed an audit identifying technical debt in the Python-only AST parser.

### v0.5.0 Objectives

1. **Feature A**: JavaScript/TypeScript AST Scanner using `esprima` Python port.
2. **Feature B**: Intelligent Severity Engine for context-aware findings.
3. **Feature C**: `.env` File Deep Scan with `.gitignore` cross-checks.

## Drift Log

- (Initial session)
- Added `esprima` dependency.
- Implemented `JsAstSecretChecker`, `SeverityEngine`, and `EnvScanner`.
- Integrated all into `Scanner`.

## Red Team Findings

- 2026-03-21 /review: 1 finding
  - **[HIGH] — Resource Exhaustion (DoS)**: `_walk_and_check` in `JsAstSecretChecker` lacked a recursion guard.
    - **File**: `src/ghostcheck/checks/ast_js_scanner.py:L28`
    - **Attack Scenario**: An attacker commits a `.js` file with an extremely deep AST (e.g., thousands of nested objects/arrays). The scanner follows the recursion, hits `sys.getrecursionlimit()`, and crashes, bypassing all subsequent checks.
    - **Impact**: Denial of Service (scanner bypass).
    - **Mitigation**: Added a `depth` parameter and enforced `self.MAX_RECURSION_DEPTH` returning early when exceeded. (FIXED)

- 2026-03-21 /review (Legacy Components Audit): 2 findings
  - **[HIGH] — Resource Exhaustion (DoS)**: Python AST parser lacked `RecursionError` catch.
    - **File**: `src/ghostcheck/checks/ast_scanner.py:L18`
    - **Attack Scenario**: Deeply nested Python code triggers a native `RecursionError` in `ast.parse()`, crashing the scanner.
    - **Impact**: Denial of Service (scanner bypass).
    - **Mitigation**: Added `RecursionError` to the exception block. (FIXED)
  - **[CRITICAL] — Path Traversal Bypass**: `_is_safe_path` used `.startswith()` for directory bounds checking.
    - **File**: `src/ghostcheck/scanner.py:L56` & `src/ghostcheck/ignorefile.py:L18`
    - **Attack Scenario**: A target inside `/repo/test-hacked` would be wrongly validated against root `/repo/test` because `startswith` matched the string prefix rather than the directory boundary. This affected both file containment limits and relative path derivation for `.gitignore` rules.
    - **Impact**: Arbitrary file access bypass for files sharing name prefixes.
    - **Mitigation**: Replaced `.startswith()` with `os.path.commonpath` in both modules. (FIXED)

## Evidence

- `tests/test_ast_js_scanner.py`
- `tests/test_severity_engine.py`
- `tests/test_env_scanner.py`
