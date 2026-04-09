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
- **Active Backlog**: none
  - When a multi-feature product spec is decomposed, the backlog path is recorded here (e.g., `.agentcortex/specs/_product-backlog.md`). Bootstrap reads this to detect ongoing product work.
- **Spec Index**:
  - `[template-import-cleanup] .agentcortex/specs/template-import-cleanup.md [Frozen] [Updated: 2026-03-06]`
  - `[red-team-skill] .agentcortex/specs/red-team-skill.md [Frozen] [Updated: 2026-03-18]`
  - `[ghostcheck-mvp] .agentcortex/specs/ghostcheck-mvp.md [Frozen] [Updated: 2026-03-11]`
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

## Ship History

### Ship-master-2026-03-06

- Feature shipped: namespaced AgentCortex-owned executable, tooling, and reference assets under `.agentcortex/`, while preserving fixed anchors and legacy wrappers for downstream compatibility.
- Tests: Pass

### Ship-codex-template-import-cleanup-namespacing-2026-03-06

- Feature shipped: normalized Work Log naming to filesystem-safe {worklog-key} paths, documented recoverable missing-log behavior for /bootstrap, /plan, and /handoff, and added regression validation for the contract.
- Tests: Pass

### Ship-codex-template-import-cleanup-namespacing-2026-03-07

- Feature shipped: added a minimal text hardening kit with repo-level text defaults, baseline-backed integrity checks, validation integration, and rollout guidance for older projects.
- Tests: Pass

### Ship-claude-gallant-haibt-2026-03-18

- Feature shipped: added Red Team / Adversarial Testing skill with auto-trigger during /review and /test phases, classification-based modes (Lite/Full/Beast), graduated blocking rules, and Work Log integration.
- Tests: Pass (markdown-only, no executable code)

### Ship-claude-admiring-turing-auto-untrack-2026-03-21

- Feature shipped: hardened deploy script with atomic .gitignore write, skills flat-file conflict guard, and post-deploy git-add hint.
- Tests: Pass (validate.sh)

### Ship-agentcortex-update-v5.3.0-2026-03-21

- Feature shipped: Updated AgentCortex framework to v5.3.0, migrated framework and project assets to `.agentcortex/` root namespace, and preserved project-specific Autopilot Protocol and pre-commit hooks.
- Tests: Pass (validate.ps1 & ghostcheck scan)

### Ship-v0.5.0-feature-multi-ast-severity-2026-03-21
- Feature shipped: implemented Multi-Language AST scanning (JS/TS via `esprima`), Intelligent Severity Engine (context-aware adjustments), and deep `.env` file security checks.
- Tests: Pass (pytest)

### Ship-feat/v0.6.0-2026-03-23
- Feature shipped: Zero-Config Onboarding (`ghostcheck init`), Git Diff scanning, Baseline/Inline suppression, and expanded 31 secret patterns.
- Tests: Pass (pytest & manual verification)

### Ship-feat/v0.7.0-2026-04-09
- Feature shipped: IaC (Terraform/K8s) scanning, CI/CD Pipeline auditing (GHA), Firebase Rules audit, Plugin Architecture, and Auto-Fix suggestions.
- Tests: Pass (pytest 34/34)
