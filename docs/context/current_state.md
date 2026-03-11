# Project Current State (vNext)

- **Project Intent**: Build **GhostCheck**, an open-source CLI security scanner for AI-assisted development workflows. Detects hallucinated packages, leaked secrets in AI outputs, and risky agent rule configurations. Built on AgentCortex v5 template.
- **Core Guardrails**:
  - Correctness first: No claim of completion without evidence.
  - Small & reversible: Prioritize small, reversible changes; avoid unauthorized refactoring.
  - Document-first: Core logic or structural changes require a Spec/ADR first.
  - Handoff gate: Non-`tiny-fix` tasks must produce a traceable handoff summary.
- **System Map**:
  - Global SSoT: `docs/context/current_state.md`
  - Task Isolation: `docs/context/work/<worklog-key>.md`
  - Active Work Log Path: derive <worklog-key> from the raw branch name using filesystem-safe normalization before any gate checks.
  - Workflows & Policies: `.agent/workflows/*.md`, `.agent/rules/*.md`
- **ADR Index**:
  - `docs/adr/ADR-001-vnext-self-managed-architecture.md`
- **Spec Index**:
  - `[template-import-cleanup] docs/specs/template-import-cleanup.md [Frozen] [Updated: 2026-03-06]`
  - [ghostcheck] docs/specs/ghostcheck-mvp.md [Frozen] [Updated: 2026-03-11]
  - When reading specs: only open files tagged with the current task's module.
- **Canonical Commands**:
  - `/bootstrap`: Task initialization & classification freeze.
  - `/plan`: Define target files, steps, risks, and rollback.
  - `/implement`: Execute implementation only when `IMPLEMENTABLE`.
  - `/review`: Check AC alignment & scope creep.
  - `/test`: Report test coverage via Test Skeleton.
  - `/handoff`: Output resumable state summary (mandatory for non-tiny-fix).
  - `/ship`: Consolidate evidence and update/archive state.
  - `ask-openrouter`: [OPTIONAL] External model delegation (natural language or `/or-*` commands). See `.agent/workflows/ask-openrouter.md`.
  - `codex-cli`: [OPTIONAL] Codex CLI delegation. See `.agent/workflows/codex-cli.md`.
- **References**:
  - `AGENTS.md`
  - `.agent/rules/engineering_guardrails.md`
  - `.agent/rules/state_machine.md`
  - `agentcortex/docs/CODEX_PLATFORM_GUIDE.md`
  - `agentcortex/docs/guides/token-governance.md`

> [!NOTE]
> This file is the Single Source of Truth for global project context only.
> Do not store per-task progress here; write progress to `docs/context/work/<worklog-key>.md`.

## Global Lessons (AI Error Pattern Registry)
>
> 3-5 high-value patterns max. Reviewed during /bootstrap.

- [Status Safety]: Ensure modular scan methods in `Scanner` prune ignored directories from `os.walk` to avoid scanning prohibited/large paths inappropriately.
- [Test Assertion]: `DemoRunner.run()` returns 0 on success; smoke tests should assert 0 and verify finding details separately instead of asserting non-zero for findings.

## Ship History
### Ship-master-2026-03-06
- Feature shipped: namespaced AgentCortex-owned executable, tooling, and reference assets under `agentcortex/`, while preserving fixed anchors and legacy wrappers for downstream compatibility.
- Tests: Pass
### Ship-codex-template-import-cleanup-namespacing-2026-03-06
- Feature shipped: normalized Work Log naming to filesystem-safe <worklog-key> paths, documented recoverable missing-log behavior for /bootstrap, /plan, and /handoff, and added regression validation for the contract.
- Tests: Pass
### Ship-codex-template-import-cleanup-namespacing-2026-03-07
- Feature shipped: added a minimal text hardening kit with repo-level text defaults, baseline-backed integrity checks, validation integration, and rollout guidance for older projects.
- Tests: Pass
### Ship-main-2026-03-11
- Feature shipped: GhostCheck MVP (v0.1.0). Implemented hallucination detection, secret scanning with file-type-aware severity, and agent rules linter. Optimized CLI for modular scans and added comprehensive smoke tests.
- Tests: Pass
