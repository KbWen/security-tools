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
  - `[auto-mode-integration] docs/specs/auto-mode-integration.md [Frozen] [Updated: 2026-06-05]`
  - `[ghostcheck-roadmap] docs/specs/ghostcheck-roadmap-v1.md [Frozen] [Updated: 2026-03-23]`
  - `[prompt-template-scanner] docs/specs/prompt_template_scanner.md [Frozen] [Updated: 2026-06-09]`
  - `[ai-marker] docs/specs/ai_marker.md [Frozen] [Updated: 2026-06-09]`
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
- [auto-mode-vs-gate]: "自動模式" couples to the human-confirmation layer, not the safety-gate layer. Hardening unattended runs = native auto-confirm (not prompt string-matching) + an INDEPENDENT reviewer; player-and-referee self-review is the core autopilot hole.
- [port-cross-refs]: When porting a skill across repos, re-validate its `§X.Y` cross-refs and `runtime_anchor` paths against the TARGET repo's section numbering (agentic-os §12.5/§5.2a ≠ security-tools §2.1/§5.2).

## Ship History

### Ship-feat/older-issues-bundle-3-2026-06-11
- Issues shipped: Resolved Issues #26, #29, and #25 to improve CLI ergonomics and command flexibility.
  - Implemented timeout override from CLI argument `--timeout` with strict type validation (blocking boolean/float bypasses), default fallback logic, and config file merging support (Issue #26).
  - Added `ghostcheck version` subcommand to print tool version, Python version, and platform information (Issue #29).
  - Added `ghostcheck check-rules` subcommand and refactored `Scanner` to apply unified post-processing (baseline, self-scan exemptions, inline ignore) with path and line number sanitization to prevent crashes on malformed inputs (Issue #25).
- Tests: Pass (182/182 tests passing).
- Review: Pass (Independent peer reviewer subagent verdict & adversarial re-review).

### Ship-feat/older-issues-bundle-2-2026-06-10
- Feature shipped: Converged next-gen AI security checkers (Epic 7, 8, 9) representing issues #6, #7, #8, #9 (RAG Issue #5 removed per instructions).
  - Implemented `LethalTrifectaDetector` to audit Python/JS ASTs for co-occurrence of private data, user input, and tool/shell execution (Issue #7).
  - Implemented `KillSwitchAuditor` (renamed from `kill_switch_auditor` to `killswitch_auditor.py`) to verify iteration limits, loop breakers, and HITL confirmations (Issue #8).
  - Implemented `SilentInstaller` (renamed from `silent_package_install_detector` to `silent_installer.py`) to block dynamic installer calls inside tools, rules, and scripts (Issue #9).
  - Implemented CLI command `ghostcheck honeypot` (direct command, no subcommands) to deploy decoy canaries (Issue #6).
- Tests: Pass (178/178 tests passing).
- Tag: Shipped as v1.1.0.


### Ship-feat/older-issues-bundle-2026-06-10

- Feature shipped: Finalized hardening of prompt template & AI marker scanners against comment bypasses, ReDoS, path traversal, name collisions, and GHA secret scanner false alarms. Resolved PR CI errors.
- Tests: Pass (149/149)

### Ship-feat/older-issues-bundle-2026-06-09
- Feature shipped: Prompt Template Security & AI Code Tracking Scanners, hardened against bypass vectors and credential validation leaks. Added `PromptTemplateScanner` for template injection/ReDoS defense, and `AIMarker` with multiline comment scanning and end-of-body Git trailer auditing. Hardened 11 core security checkers (including PrivilegeAuditor key masking and TamperAuditor SQL/Batch comments) and reporters against path traversal, logical/CORS bypasses, name collisions, evasion syntax, and plaintext secret leakage.
- Tests: Pass (145/145)

### Ship-fix/bug-bundle-2026-06-08
- Feature shipped: Resolved five outstanding bugs in the repository issue tracker (Issues #10, #11, #15, #16, #17) to stabilize the CLI security scanner (GhostCheck), prevent crashes, and reduce false positives.
- Tests: Pass

### Ship-test/antigravity-test-2026-06-05
- Feature shipped: Verified Antigravity 2.0 runtime behaviors (autopilot execution, isolated subagent review, and recommended skill loading) and resolved pre-existing local CI check failures in validate scripts.
- Tests: Pass

### Ship-fix/auto-mode-honest-default-2026-06-05
- Quick-win shipped: make Auto-Mode independence **honest by default** (SUPERSEDES the framing in the capability-aware entry below, after per-platform capability research).
  - Research (3 agents) + expert panel (3 agents) confirmed: **NONE** of Claude Code / Codex / Antigravity 2.0 reliably auto-dispatches an isolated-context reviewer unattended BY DEFAULT (Claude=model-discretion/hooks; Codex="only when explicitly asked"/`codex exec`; Antigravity 2.0=`start_subagent` needs CapabilitiesConfig + teamwork=Ultra-only research preview). Skill auto-activation is probabilistic on all three. → The prior "PRIMARY=subagent, FALLBACK=legacy 1.x" framing was dishonest.
  - Fix: degraded clean-slate self-review is now the **honest DEFAULT**; true isolated review is an explicit per-platform OPT-IN; independence counts only with proof (mechanism + executor). Ship `⚠️ shipped without independent review` flag flipped to **default-ON, suppressed only on affirmative proof** (closes the silent-clean-ship gap). Files: AGENTS.md §Auto-Mode Contract, review.md, autopilot.md.
  - Also: fixed `production-readiness` 1:1 sync (Antigravity `.agent/` path was a 14-line stub vs 82-line body); hardened validate.sh/.ps1 to enforce directory-form skill 1:1 sync (was unchecked — the gap that let the stub ship).
- **Follow-ups**: (a) RESOLVED — frozen spec `auto-mode-integration.md` AC2 amended to honest-default (owner-approved unfreeze→amend→refreeze). (b) PARTIAL — `test_results.txt` BOM stripped + `deploy.ps1` canary corrected (it pinned invalid PowerShell). **NOTE**: `validate.sh` was already red on `main` from a CHAIN of pre-existing failures unrelated to auto-mode; remaining are STALE DOC CANARIES (`README_zh-TW.md` etc. are valid UTF-8 — the validator pins outdated literal phrases). Separate canary-repoint cleanup needed; NOT bundled here to avoid fragile scope creep.
- Verified by independent acx-reviewer (PASS).

### Ship-fix/independence-capability-aware-2026-06-05
- Quick-win shipped: make Auto-Mode independent review **capability-aware** (fixes a false-assurance破口 flagged by user).
  - Root cause: "independent subagent review" assumed a spawn primitive Antigravity might lack → silent self-review masquerading as independent.
  - Research (web): Antigravity 2.0 (2026-05-19) DOES auto-spawn dynamic subagents with isolated context; 1.x has only manual workspace agents; Claude Code (Task) + Codex CLI also provide isolated dispatch.
  - Fix: `review.md` §Auto-Mode Independence Rule + `AGENTS.md` §Auto-Mode Contract — PRIMARY dispatch to an isolated-context reviewer (Antigravity 2.0+/Claude Code/Codex/ask-openrouter); FALLBACK (legacy) = clean-slate self-review marked `independence: degraded (self-review)`, never silent; degraded MAY auto-ship but MUST carry a loud `⚠️ shipped without independent review` flag. No hard gate weakened.
- Verified by independent acx-reviewer (PASS). 

### Ship-fix/skill-application-wiring-2026-06-05
- Quick-win shipped: make skill application reliable in unattended Auto-Mode (follow-up to auto-mode-integration).
  - `AGENTS.md` §Skill Safety item 4 "Phase-Entry Skill Application": every non-tiny-fix phase applies Work Log Recommended Skills relevant to the phase. Hybrid relevance: use `phases:` when the skill declares it (the 5 domain skills do — authoritative, kept), fall back to `description` when absent (the 12 process skills). Fixes silently-skipped skills in unattended runs.
  - `review.md` Skill-Aware condition fixed to the same hybrid (was gated on a `phases:`-equality that the recommended process skills never satisfied).
  - `AGENTS.md` Auto-Mode Contract Effect: added ship-phase confirmation (auto-approved ONLY after ship Gate pass AND independent review PASS) — closes an autopilot /ship stall without weakening gates.
- No skill files touched (17 skills have inconsistent file/dir structure; avoided amplifying it). Verified by independent acx-reviewer (caught a false `phases:` premise → corrected against self-verified ground truth).

### Ship-feat/auto-mode-integration-2026-06-05
- Feature shipped: Auto-Mode (Autopilot) hardening — integrate agentic-os capabilities while preserving Antigravity 自動模式.
  - Added `AGENTS.md` §Auto-Mode (Autopilot) Contract: native auto-approval of Runtime v5 human-confirmation handshakes (§3/§6/§8) when `Mode: autopilot`, replacing autopilot.md's fragile prompt string-matching. ALL safety gates (verdict, Evidence, Security/Red-Team, No-Bypass, Confidence) remain hard-enforced.
  - Added `review.md` §Auto-Mode Independence Rule: unattended `/review` MUST run as an independent fresh-context subagent (no player-and-referee self-approval).
  - Ported `production-readiness` skill (review + ship observability checks); registered in bootstrap auto-recommend.
  - Enriched workflow/skill `description:` metadata for accurate unattended intent-routing.
- Tests: Structural validation pass (governance docs/YAML; no code). Verified by two independent acx-reviewer passes (NOT READY → 4 fixes → PASS).

### Ship-feat/systematic-false-positive-reduction-2026-05-31
- Optimization shipped: Comprehensive Scanner Optimization, Casing Bug Fixes, Comment-based False Positive Elimination, and Security Hardening.
  - Fixed an initialization ordering bug in `scanner.py` where `ignore_matcher` was initialized after plugins, and missing constructor arguments skipped `EnvScanner` loading.
  - Restricted `EnvScanner` to target actual env files and filter out templates or generic files.
  - Implemented Shannon entropy checking and vocabulary/path filters in `secrets.py` for "Generic Secret Key" pattern to eliminate false positives on common variables, headers, and paths.
  - Restructured `APILinter` to only scan backend/frontend source code files.
  - Fixed a case-sensitivity issue in `ci_auditor.py` for Fastlane configuration file checks (matching lowercase `fastfile`, `matchfile`, `appfile`).
  - Fixed shadow AI SDK import false positives in `shadow_ai.py` by excluding comments (stripping `#` for Python, stripping `//` and `/* ... */` for JS/TS).
  - Implemented file pre-filter scoping in 7 major scanners (`firebase_rules_auditor`, `mobile_config_auditor`, `privilege_auditor`, `shadow_ai`, `vuln_scanner`, `entropy_scanner`, `agent_rules`) to prevent opening and reading non-target files, reducing redundant I/O operations by 90%+.
  - Hardened `privilege_auditor.py` to support detecting broad Windows user home folder mounts (e.g. `C:\Users\username`) in MCP configurations and enforced case-insensitivity.
  - Patched `entropy_scanner.py` security bypass vulnerability where code keywords flanked by dashes flank-matched word boundaries and bypassed high-entropy secret scanning. Enforced case-insensitivity for cert hex hash exclusions.
- Tests: Pass (105/105 tests passing, Grade A 100/100 self-scan score).

### Ship-feat/optimize-trust-and-docs-2026-05-31
- Optimization shipped: Repository Trust, Documentation, and Packaging (v1.0.3).
  - Added MIT LICENSE file in the root.
  - Aligned hardcoded version string "1.0.0" across `cli.py`, `scanner.py`, and `sarif_reporter.py` to load package version dynamically.
  - Fixed a critical instantiation bug where Go, Dart, Java, JS, and generic AST scanners were silently skipped in production scans due to missing configuration arguments and mismatched module name filters.
  - Reduced false positives by implementing strict file-scoping rules: `AgentRulesLinter` now only scans agent rule files (`.cursorrules`, `.mdc`, or markdown files with rule-related names), and `MCPAuditor` only scans MCP config files (`mcp.json`, `mcp_config.json`, etc.) or MCP server implementations. This eliminated over 460+ false positives in lockfiles (`uv.lock`), build scripts (`Makefile`), and data mappings (`owasp_mapping.json`).
  - Added `scanner.py` to the self-scan exemptions list to prevent inline ignore syntax from triggering malicious bypass warnings.
  - Optimized `pyproject.toml` package-data to recursively include `data/` JSON and demo fixture files.
  - Refactored `Makefile`'s `demo` target to run with soft-fail and demo fixtures.
  - Updated `.gitignore` to exclude temporary report files and scan test workspaces.
  - Updated `README.md` and `README_zh-TW.md` with clean layout, dynamic version, test guides, and MIT License badge.
- Tests: Pass (104/104 tests passing, added AST scanner load checks).

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
