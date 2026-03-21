---
status: frozen
title: Template Import Cleanup
branch: master
created: 2026-03-06
---

# Template Import Cleanup

## Goal
Reorganize this template repository so downstream projects can import AgentCortex without root-level naming collisions, by keeping only platform-required anchors in fixed locations and moving other AgentCortex-owned assets under a canonical `agentcortex/` namespace.

## Acceptance Criteria
1. The spec defines a placement rule of "root path requires justification"; any AgentCortex-owned asset that is not a fixed platform anchor must live under a canonical `agentcortex/` path.
2. The spec explicitly lists the fixed anchors that remain in stable locations because platform integrations, governance loading rules, or published entrypoints require them.
3. A canonical namespace layout is defined for movable assets, including at minimum the intended roles of `agentcortex/bin/`, `agentcortex/tools/`, `agentcortex/docs/`, and `agentcortex/templates/`.
4. Public compatibility entrypoints that must remain callable from legacy paths are identified as thin wrappers whose implementations delegate into the canonical `agentcortex/` paths.
5. A migration map exists for every in-scope path touched by this cleanup, marking each path as fixed anchor, move into namespace, wrapper to keep, or downstream-local state.
6. Verification covers at least: repository integrity checks, deploy path consistency, wrapper-to-canonical path consistency, and a downstream import review showing reduced collision risk at repository root.

## Non-goals
- Redesigning workflow semantics or agent governance content.
- Moving files that are hard-required by Codex, Antigravity, Claude, or AGENTS-loading behavior without an explicit compatibility wrapper plan.
- Performing the file moves in this spec phase.
- Broadly renaming user-facing concepts unless required to establish a stable namespace boundary.

## Constraints
- Existing stable entrypoints must be treated as compatibility-sensitive until wrappers and migration notes are defined.
- The namespace strategy must preserve cross-platform support for Codex, Antigravity, and Claude adapters.
- Downstream repositories must still be able to bootstrap from documented public entrypoints during the migration period.
- Work within repository governance: task state stays in the Work Log, and `docs/context/current_state.md` is not updated until `/ship`.

## API / Data Contract
- Fixed-anchor candidates currently in scope: `AGENTS.md`, `CLAUDE.md`, `.agent/`, `.agents/`, `.antigravity/`, `.claude/`, `.codex/`, `codex/`, `docs/context/`, `docs/specs/`, and `docs/adr/`.
- Compatibility-wrapper candidates currently in scope: `deploy_brain.sh`, `deploy_brain.ps1`, `deploy_brain.cmd`, `tools/validate.sh`, `tools/validate.ps1`, and `tools/validate.cmd`.
- Canonical namespace root proposed in this spec: `agentcortex/`.

## Canonical Namespace Layout
| Path | Role | Notes |
| --- | --- | --- |
| `agentcortex/bin/` | Canonical executable implementations | Shell, PowerShell, or CMD-compatible implementations live here; root-level scripts become wrappers if they must stay public. |
| `agentcortex/tools/` | Maintenance and verification tooling | Audit, validation helpers, and non-anchor support scripts move here by default. |
| `agentcortex/docs/` | AgentCortex-owned reference material | Shipped docs that are not governance anchors should live here instead of the downstream repo's generic `docs/` root. |
| `agentcortex/templates/` | Template-only assets and scaffolding | Files copied or rendered during deploy live here unless a platform requires another path. |

## Fixed Anchors
| Path Group | Why Fixed | Decision |
| --- | --- | --- |
| `AGENTS.md`, `CLAUDE.md` | Cross-platform governance entrypoints are expected at repository root. | KEEP AS FIXED ANCHOR |
| `.agent/`, `.agents/`, `.antigravity/`, `.claude/`, `.codex/`, `codex/` | Platform integrations already require or strongly assume these namespaced locations. | KEEP AS FIXED ANCHOR |
| `docs/context/`, `docs/specs/`, `docs/adr/` | Current governance rules and workflows load these paths explicitly. | KEEP AS FIXED ANCHOR |

## File Placement Policy
| Path Group | Classification | Decision | Notes |
| --- | --- | --- | --- |
| Fixed anchors listed above | Downstream entrypoint or governance anchor | KEEP AS-IS | These remain outside `agentcortex/` only because an external contract already depends on them. |
| `deploy_brain.*` | Public compatibility entrypoint | KEEP PATH, CONVERT TO WRAPPER | Public root-level names may remain, but implementation should delegate into `agentcortex/bin/`. |
| `tools/validate.*` | Public compatibility entrypoint | KEEP PATH, CONVERT TO WRAPPER | Preserve existing invocation patterns while moving implementation into `agentcortex/bin/` or `agentcortex/tools/`. |
| AgentCortex-owned maintenance tools | AgentCortex support asset | MOVE TO `agentcortex/tools/` | Default destination for audit or helper scripts that do not need a fixed public path. |
| AgentCortex-owned shipped reference docs outside governance anchors | AgentCortex support asset | MOVE TO `agentcortex/docs/` | Avoid colliding with a downstream project's own `docs/` taxonomy. |
| Template-only scaffolding or copy-source assets | Template-maintenance-only asset | MOVE TO `agentcortex/templates/` | Keep template internals isolated from downstream project structure. |
| `docs/context/current_state.md`, `docs/context/work/`, `docs/context/archive/`, `docs/context/private/` | Downstream-local state | KEEP PATH; IGNORE RUNTIME STATE ONLY | Governance anchors stay fixed, but ignore scope remains limited to runtime or local state. |

## Migration Map
| Path | Current Role | Action | Compatibility Note |
| --- | --- | --- | --- |
| `deploy_brain.sh` | Primary deploy entrypoint | Keep as wrapper | Delegate to `agentcortex/bin/deploy.sh`; keep root path for compatibility. |
| `deploy_brain.ps1` | Windows deploy wrapper | Keep as wrapper | Delegate to canonical deploy implementation under `agentcortex/bin/`. |
| `deploy_brain.cmd` | Windows CMD deploy wrapper | Keep as wrapper | Delegate to canonical deploy implementation under `agentcortex/bin/`. |
| `tools/validate.sh` | Primary validation entrypoint | Keep as wrapper | Delegate to canonical validation implementation under `agentcortex/bin/` or `agentcortex/tools/`. |
| `tools/validate.ps1` | PowerShell validation entrypoint | Keep as wrapper | Same wrapper policy as shell validation entrypoint. |
| `tools/validate.cmd` | CMD validation wrapper | Keep as wrapper | Same wrapper policy as other validation entrypoints. |
| `tools/audit_ai_paths.sh` | Maintenance helper | Move to `agentcortex/tools/` | Root-level `tools/` should not accumulate AgentCortex-only helpers. |
| Shipped reference docs outside `docs/context/`, `docs/specs/`, `docs/adr/` | Reference docs | Move to `agentcortex/docs/` | Keep governance anchors fixed, but isolate AgentCortex-owned reference docs from downstream doc structure. |
| Template copy-source assets used only during deploy | Template internals | Move to `agentcortex/templates/` | Internal assets should not pollute downstream top-level or generic folders. |
| `docs/context/current_state.md` | Governance runtime seed | Keep and ignore by exact file | Fixed anchor due to governance rules; ignore remains narrow. |
| `docs/context/work/`, `docs/context/archive/`, `docs/context/private/` | Governance runtime state | Keep and ignore directory | Fixed anchors for governance layout; hidden only because they are runtime or local state. |

## Verification Notes
- Root-level paths after cleanup should be explainable as either fixed anchors or compatibility wrappers.
- Canonical implementations should be reachable from wrappers through explicit paths under `agentcortex/`.
- Ignore defaults must not hide moved canonical assets unless they are runtime or local-state outputs.

## File Relationship
REPLACES the previous draft assumptions in `docs/specs/template-import-cleanup.md` about keeping most existing public paths in place. The governing spec file path remains the same; this draft supersedes the earlier placement policy.