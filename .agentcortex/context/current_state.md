# Project Current State (vNext)

- **Project Intent**: Build a self-managed Agent OS for Codex Web / Codex App / Google Antigravity to reduce human procedural burden and continuously lower token costs.
- **Core Guardrails**:
  - Correctness first: No claim of completion without evidence.
  - Small & reversible: Prioritize small, reversible changes; avoid unauthorized refactoring.
  - Document-first: Core logic or structural changes require a Spec/ADR first.
  - Handoff gate: Non-`tiny-fix` tasks must produce a traceable handoff summary.
- **System Map**:
  - Global SSoT: `.agentcortex/context/current_state.md`
  - Task Isolation: `.agentcortex/context/work/<worklog-key>.md`
  - Active Work Log Path: derive <worklog-key> from the raw branch name using filesystem-safe normalization before any gate checks.
  - Workflows & Policies: `.agent/workflows/*.md`, `.agent/rules/*.md`
- **ADR Index**:
  - `.agentcortex/adr/ADR-001-vnext-self-managed-architecture.md`
- **Active Backlog**: `docs/specs/_product-backlog.md`
  - AI-Era Security Features backlog (MCP, Agent Rules, LLM Supply Chain, Agentic Workflow, OWASP LLM Top 10). Expanded Epic 7 & 8 on 2026-04-13.
- **Spec Index**:
  - `[agent-least-privilege-audit] docs/specs/agent-least-privilege-audit.md [Frozen] [Updated: 2026-05-20]`
  - `[template-import-cleanup] .agentcortex/specs/template-import-cleanup.md [Frozen] [Updated: 2026-03-06]`
  - `[red-team-skill] .agentcortex/specs/red-team-skill.md [Frozen] [Updated: 2026-03-18]`
  - `[ghostcheck-mvp] .agentcortex/specs/ghostcheck-mvp.md [Frozen] [Updated: 2026-03-11]`
  - `[shadow-ai-detection] docs/specs/shadow-ai-detection.md [Frozen] [Updated: 2026-05-20]`
  - `[ghostcheck-roadmap] docs/specs/ghostcheck-roadmap-v1.md [Frozen] [Updated: 2026-03-23]`
  - When reading specs: only open files tagged with the current task's module.
- **Canonical Commands**:
  - `/spec-intake`: Import external specs (from other LLMs, documents, or natural language). Handles large product specs via decomposition. Runs before `/bootstrap`.
  - `/bootstrap`: Task initialization & classification freeze.
  - `/plan`: Define target files, steps, risks, and rollback.
  - `/implement`: Execute implementation only when `IMPLEMENTABLE`.
  - `/review`: Check AC alignment & scope creep.
  - `/test`: Report test coverage via Test Skeleton.
  - `/handoff`: Output resumable state summary (mandatory for non-tiny-fix).
  - `/decide`: Record key decisions with reasoning to prevent cross-session re-derivation.
  - `/test-classify`: Auto-select test depth and evidence format based on task classification.
  - `/ship`: Consolidate evidence and update/archive state.
  - `ask-openrouter`: [OPTIONAL] External model delegation (natural language or `/or-*` commands). See `.agent/workflows/ask-openrouter.md`.
  - `codex-cli`: [OPTIONAL] Codex CLI delegation. See `.agent/workflows/codex-cli.md`.
- **References**:
  - `AGENTS.md`
  - `.agent/rules/engineering_guardrails.md`
  - `.agent/rules/state_machine.md`
  - `.agentcortex/docs/CODEX_PLATFORM_GUIDE.md`
  - `.agentcortex/docs/guides/token-governance.md`
  - `.agentcortex/docs/guides/context-budget.md`

> [!NOTE]
> This file is the Single Source of Truth for global project context only.
> Do not store per-task progress here; write progress to `.agentcortex/context/work/<worklog-key>.md`.

## Global Lessons (AI Error Pattern Registry)
>
> 3-5 high-value patterns max. Reviewed during /bootstrap.

- [Global Memory]: Branch-local lessons are lost after archival. Use Global Lessons Registry for persistence.
- [Format Safety]: Do not copy line numbers from view tools; they break file edits.
- [Path Rewrite Guard]: Namespace migrations should validate for accidental double-prefix replacements like `agentcortex/agentcortex/...` immediately after bulk path rewrites.
- [Wrapper Validation]: Validation checks for wrapper files should assert behaviorally equivalent path construction patterns, not only one literal path string representation.
- [Bash Portability]: Shell validation entrypoints should prefer portable `grep`-based checks over environment-specific `rg` assumptions when they are part of cross-platform integrity gates.
- [Work Log Key]: Resolve filesystem-safe worklog keys from raw branch names before gate checks; missing active logs are recoverable, while missing handoff references or evidence remain hard failures.

GLOBAL-CANDIDATE [Patch Path Fallback]: When `apply_patch` is unstable on this Windows workspace, prefer repo-local safe whole-file rewrites only for newly added files or tightly scoped text-only files, then immediately re-verify with `git diff --check`.
- [Detector Validation]: New integrity checks must be validated against real repo bytes before baselining, otherwise pure-LF files can be falsely classified as mixed EOL and pollute the baseline.
- [Shell Dependency Guard]: Cross-platform validation entrypoints must not add new hard runtime dependencies unless the template explicitly requires them and the migration path is documented.
- [regex-precision]: Broad regex patterns for secrets (like Generic) should be paired with low severity or high-entropy checks to avoid CLI noise.
- [windows-python-path]: Windows environments often require `python -m module` instead of direct script calls if the PATH is not perfectly aligned.
- [Exception Handling]: Silent 'except Exception: pass' violates engineering guardrails; always use the standard 'logging' module (e.g. logger.debug) to preserve debugging trails without polluting JSON or SARIF standard outputs.
- [Parallel-Scanning]: For I/O bound SAST scanners, using `ThreadPoolExecutor` with single-pass file distribution significantly outperforms serial multi-pass scans (O(N) vs O(M*N)).
- [Terminal-Resilience]: Global `sys.stdout` reconfiguration with `errors='replace'` is mandatory for Windows (CP950) terminal compatibility when using high-fidelity Unicode/Emoji icons.
- [Harden-Packaging]: Distributed data files must be explicitly declared in `pyproject.toml` [tool.setuptools.package-data] for inclusion in wheel/sdist.
- [Harden-Encoding]: Use bytes processing for CLI subprocesses to avoid decoding errors on non-UTF8 terminals (Windows).
- [Harden-Path-Safety]: Windows multi-drive environments require explicit drive-letter comparison in path traversal checks.
- [Harden-Encoding]: Ensure json.load uses encoding="utf-8" when reading context keywords.
- [FP-Exemption]: Auto-ignore ghostcheck self-scans or lower their severity to avoid pre-commit blockages on self-code.

## Ship History

### Ship-feat/shadow-ai-detection-2026-05-22 (Phase 6, 7, 8)
- Feature shipped: Red Team Hardening & Reporter Decoupling (v1.0.3).
  - Phase 6: Decoupled all 24 scanners into `BaseScannerPlugin` and managed via `PluginManager`.
  - Phase 7: Fixed 4 Red Team vulnerabilities: Chaos Protection Bypass (line truncation), Local Plugin RCE (trust environment variable), Inline Ignore Abuse (strict comment enforcement), and Directory Traversal in ignore rules. Added `TamperAuditor`.
  - Phase 8: Extracted reporters (`console`, `json`, `html`, `owasp-llm`, `sarif`) into `BaseReporterPlugin`. Fixed SARIF rule_id mapping for dynamic schemas.
- Tests: Pass (103/103 tests passing, including SARIF and Bypass regression tests).

### Ship-feat/shadow-ai-detection-2026-05-20
- Feature shipped: Shadow AI Detection (v1.0.2). Added `ShadowAIDetector` checking unauthorized Python/JS AI SDKs, manifest file dependencies, local LLM endpoints, environment configurations, and recommended VS Code extensions (GSA-01 to GSA-06).
- Tests: Pass (pytest 8/8 shadow-ai tests, 90/90 total tests passing)

### Ship-feat/agent-least-privilege-audit-2026-05-20
- Feature shipped: Agent Least Privilege Audit (v1.0.2). Added `PrivilegeAuditor` checking GITHUB_TOKEN scope audits (GPA-01 to GPA-03), MCP config broad mounts and sudo audits (GPA-04, GPA-05), and command-line/client-side API key exposures (GPA-06, GPA-07).
- Tests: Pass (pytest 9/9 privilege-specific tests, 82/82 total tests passing)

### Ship-fix/fp-reduction-and-context-intelligence-2026-05-20
- Feature shipped: Context Intelligence & False Positive Reduction (v1.0.1). Added multilingual ContextAuditor, regex negative lookbehinds for shell paths, and minified file security protections.
- Tests: Pass

> [!NOTE]
> Older ship history has been moved to [.agentcortex/context/archive/ship_history_archived.md](file:///.agentcortex/context/archive/ship_history_archived.md) to save context tokens.

### Ship-feat/v0.8.0-2026-04-09
- Feature shipped: AI Agent Security Foundation (Epic 1-5). Fixed unpinned npx/mcp server risks, enhanced agent rules (Unicode injection/sensitive paths), AI supply chain auditing, and OWASP LLM Top 10 compliance mapping.
- Tests: Pass (pytest 7/7 new features)

### [v1.0.0] - 2026-04-17
**Status**: COMPLETED ✅
**Focus**: Universal Scanner & Framework Presets

#### Key Improvements:
- **Framework Presets**: Added `ghostcheck.presets.manager` to auto-detect and configure templates for Next.js, Flutter, Django, FastAPI, and Terraform.
- **Robust Baseline**: Swapped brittle, line-based cache suppressions with resilient content hashing (`Scanner._get_finding_hash`).
- **Module Filtering**: Reduced I/O overhead by skipping unrelated rule sets (e.g. Docker checks isolated purely to infrastructure profiles).
- **Scanner Refactoring**: Hardened Docker scanning rules and isolated CI/CD logic.

#### Evidence:
- Testing: `test_v1_0_0_presets.py` and `test_robust_baseline.py` PASSED dynamically.
- CLI Integration: Presets fully supported in `ghostcheck init` and `ghostcheck scan`.

### [v0.9.1] - 2026-04-17
**Status**: COMPLETED ✅
**Focus**: OWASP LLM Compliance Reporting

#### Key Improvements:
- **OWASP LLM Support**: Implemented `--format owasp-llm` for standardized AI security reporting.
- **Mapping Engine**: Added `owasp_mapping.json` to link the internal finding IDs with LLM01-LLM10 categories.
- **Remediation Database**: Integrated OWASP-aligned remediation advice into the compliance report.

#### Evidence:
- UI Testing: `tests/test_owasp_reporter.py` PASSED
- CLI Verification: `scan --format owasp-llm` PASSED with compliance ratio calculation.

### [v0.9.0] - 2026-04-16
**Status**: COMPLETED ✅
**Focus**: Installation Resilience & External User Hardening

#### Key Improvements:
- **Packaging Resilience**: Fixed `pyproject.toml` syntax for classifiers and included `package-data` for JSON rules.
- **Windows Hardening**: Forced UTF-8 encoding for stdout/stderr and fixed `UnicodeDecodeError` when reading `.ghostcheckignore` and secret rules.
- **Dependency Degradation**: Added `ImportError` guards for `requests` and `esprima`.
- **Corporate Proxy Support**: Implemented proxy configuration in `HallucinationChecker`, `VulnScanner`, and `SecretValidator`.
- **Bug Fixes**: 
    - Fixed missing `hashlib` import breaking the results cache mechanism.
    - Fixed CLI file locking when using `--output`.
    - Synchronized package version in `__init__.py`.

#### Evidence:
- UI Testing: `tests/test_cli.py` PASSED
- Resilience Testing: `tests/test_harden_resilience.py` PASSED
- Integrity Testing: `tests/test_cache_integrity.py` PASSED
- Total: 54/54 tests PASSED

---

## Deployment & Readiness
- **Main Branch**: Correctly synchronized with all resilience fixes.
- **Documentation**: README updated with installation instructions and proxy settings.
- **Main Branch**: Implemented and synchronized GhostCheck v1.0.0 (Framework Presets & Robust Baseline).
- **Backlog**: Preparing for Advanced Rule Integrations (v1.1.0+).
