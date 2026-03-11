---
Owner: codex-master-20260306
Branch: master
Classification: feature
Classified by: Codex (GPT-5)
Frozen: true
Created Date: 2026-03-06
Recommended Skills:
  - writing-plans
  - executing-plans
---

## Session Info
@gpt-5:codex-app:2026-03-06 00:00:00 +08:00
- Agent: Codex (GPT-5)
- Session: 2026-03-06 00:00:00 +08:00
- Platform: Codex App

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO
- Scope Pivot: YES
- Scope Pivot Note: The cleanup direction has shifted from ignore-boundary hardening to a namespace-root policy where non-anchor AgentCortex assets should default under `agentcortex/`.

## Goal
- Reorganize this template repository so imported projects keep a clean structure, avoid naming collisions, and do not inherit unnecessary tracked or unignored artifacts.

## Constraints
- Do not move or rename files before an explicit migration plan is approved.
- Protect downstream repositories from path pollution and default tracked clutter.
- Keep changes small and reversible.
- Preserve classification freeze in this Work Log; treat the namespace-root redesign as a spec-level pivot that must be planned explicitly before implementation.

## Initial Findings
- Multiple platform-specific directories are tracked at repository root: `.agent`, `.agents`, `.antigravity`, `.claude`, `.codex`, `codex`.
- `.gitignore` currently ignores only a small subset of local artifacts.
- Install or validation entrypoints appear to be `deploy_brain.*` and `tools/validate.*`; test or install surface needs explicit scoping before implementation.
- Downstream import friction is broader than ignore behavior alone: generic roots like `tools/` and top-level scripts also create naming-collision risk.

## Next
- Redraft the cleanup spec around fixed anchors, canonical `agentcortex/` namespace paths, and thin compatibility wrappers.

## Spec
- Path: docs/specs/template-import-cleanup.md
- Status: frozen
- Scope: repository import boundary cleanup, canonical namespace layout, compatibility-wrapper policy, and downstream collision reduction.

## Risks (from /plan)
- Root-wrapper drift: legacy entrypoints may stop matching canonical implementations if wrappers are updated without the delegated scripts; mitigate by moving real logic first and making wrappers as thin as possible.
- Anchor misclassification: moving a path that is implicitly required by platform workflows could break bootstrap or governance loading; mitigate by treating only the spec-listed anchors as movable and validating each move against current workflow references.
- Migration sprawl: relocating docs, tools, and templates together can create a wide diff that is hard to verify or revert; mitigate by executing in phases with one namespace family at a time and preserving rollback-safe wrappers.
- Ignore-policy regression: new canonical paths may accidentally be hidden or left noisy in downstream repos; mitigate by re-validating emitted `.gitignore` behavior after each namespace batch.
## Implementation Notes
- Step 1 complete: classified the initial namespace batch around fixed anchors versus movable executable and maintenance assets.
- Step 2 complete: created canonical `agentcortex/bin/` and `agentcortex/tools/` implementations for deploy, validate, and audit flows.
- Step 3 complete: converted `deploy_brain.*` and `tools/validate.*` into thin wrappers that delegate into the canonical `agentcortex/` implementations.
- Step 4 complete: moved non-anchor source-side reference docs from `docs/` and `docs/guides/` into `agentcortex/docs/` and updated active references plus canonical deploy or validate sources accordingly.

## Evidence
- Verified with `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\validate.ps1` -> passed.
- Verified with Git Bash wrapper flow: `./tools/validate.sh` -> passed.
- Verified downstream deploy behavior with `powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_brain.ps1 -Target .\.tmp_template_import_cleanup_smoke` plus `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\template_import_cleanup_smoke.ps1 -Target .\.tmp_template_import_cleanup_smoke` -> passed.
- Verified deploy_brain.sh with unrestricted Git Bash to ./.tmp_template_import_cleanup_bash_smoke, then re-checked the deployed layout with powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\template_import_cleanup_smoke.ps1 -Target .\.tmp_template_import_cleanup_bash_smoke -> passed.
- Confirmed the moved audit helper now lives at `agentcortex/tools/audit_ai_paths.sh`, while public validation and deploy entrypoints remain callable from legacy root paths.
- Confirmed source-side non-anchor reference docs now live under `agentcortex/docs/`, and active entry documents (`README.md`, `README_zh-TW.md`, `AGENTS.md`, `docs/context/current_state.md`) point at the new canonical locations.
- Prior ignore-hardening evidence remains valid: managed downstream `.gitignore` blocks still replace legacy blocks and still only ignore runtime or local-state noise.

## Test Files
- `tests/template_import_cleanup_smoke.ps1`

## Handoff Delta
- Landed the first executable namespace batch without moving fixed governance anchors.
- Canonical implementations now live under `agentcortex/bin/`; root and `tools/` entrypoints are compatibility wrappers.
- Non-anchor reference docs and guides were physically moved into `agentcortex/docs/`, so source and downstream layouts now align.
- Remaining follow-up scope is mostly documentation polish and any optional cleanup of historical references, not deploy or validate mechanics.

## Resume
- State: SHIPPED
- Completed: redrafted the cleanup spec; created the canonical `agentcortex/` executable namespace; wrapped legacy deploy and validate entrypoints; moved the audit helper under `agentcortex/tools/`; moved non-anchor source-side docs and guides under `agentcortex/docs/`; added a persistent downstream smoke test under `tests/`; verified PowerShell and Bash validation paths; verified downstream namespaced deploy output.
- Next: archived after `/ship`; no active follow-up required for this branch.
- Context: Fixed governance and platform anchors remain in place, while executable, maintenance, and reference assets now live under `agentcortex/` so imported downstream repos avoid generic root collisions.

## Lessons
- [Path Rewrite Guard][GLOBAL-CANDIDATE]: Namespace migrations should validate for accidental double-prefix replacements like `agentcortex/agentcortex/...` immediately after bulk path rewrites.
- [Wrapper Validation]: Validation checks for wrapper files should assert behaviorally equivalent path construction patterns, not only one literal path string representation.
- [Bash Portability][GLOBAL-CANDIDATE]: Shell validation entrypoints should prefer portable `grep`-based checks over environment-specific `rg` assumptions when they are part of cross-platform integrity gates.
- [Path Rewrite Guard][GLOBAL-CANDIDATE]: Namespace migrations should validate for accidental double-prefix replacements like `agentcortex/agentcortex/...` immediately after bulk path rewrites.
- [Wrapper Validation]: Validation checks for wrapper files should assert behaviorally equivalent path construction patterns, not only one literal path string representation.
- [Bash Portability][GLOBAL-CANDIDATE]: Shell validation entrypoints should prefer portable `grep`-based checks over environment-specific `rg` assumptions when they are part of cross-platform integrity gates.