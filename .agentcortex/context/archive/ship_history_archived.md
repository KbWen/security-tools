# Archived Ship History

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
