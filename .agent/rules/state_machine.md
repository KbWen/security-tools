# Canonical Development State Machine

## Defined States

`INIT` -> `BOOTSTRAPPED` -> `CLASSIFIED` -> [`SPECIFIED`] -> `PLANNED` -> `IMPLEMENTABLE` -> `IMPLEMENTING` -> `REVIEWED` -> `TESTED` -> `SHIPPED`

## Allowed Transitions

AI MUST self-enforce this phase order. Users may trigger transitions via slash commands (as shortcuts) OR via natural language — AI determines the appropriate phase regardless of wording.

- `INIT` --(external spec provided)--> `INIT` [runs `/spec-intake`; produces frozen spec + optional `_product-backlog.md`; loops back to INIT until spec is frozen]
- `INIT` --(context loaded)--> `BOOTSTRAPPED` [if frozen external spec exists, bootstrap reads it directly — Bootstrap Lite path]
- `BOOTSTRAPPED` --(task classified)--> `CLASSIFIED`  [Sets: Guardrails Mode (Full|Quick|Lite), Context Budget tier]
- `CLASSIFIED` --(research / brainstorm iteration)--> `CLASSIFIED`
- `CLASSIFIED` --(spec artifact created in `.agentcortex/specs/`)--> `SPECIFIED`
- `SPECIFIED` --(plan produced)--> `PLANNED`
- `CLASSIFIED` --(plan produced)--> `PLANNED`  [ONLY for: `tiny-fix`, `quick-win`, `hotfix`]
- `PLANNED` --(gate pass)--> `IMPLEMENTABLE`
- `IMPLEMENTABLE` --(begin implementation)--> `IMPLEMENTING`
- `IMPLEMENTING` --(review pass)--> `REVIEWED`
- `REVIEWED` --(test pass)--> `TESTED`
- `TESTED` --(ship executed)--> `SHIPPED`

## Spec Gate (Hard)

- Classifications `feature` and `architecture-change` MUST reach `SPECIFIED` before planning.
- `SPECIFIED` requires a corresponding `.agentcortex/specs/<feature>.md` artifact with `status: draft` or `status: frozen`.
- `tiny-fix`, `quick-win`, and `hotfix` may transition directly from `CLASSIFIED` to `PLANNED`.

## Read-Only Actions (No State Change)

- Listing help, available commands, generating test skeletons, producing handoff summaries

## Hard Gates

- Non-`tiny-fix` tasks MUST complete a handoff phase before `SHIPPED`. Required references:
  1. ✅ `.agentcortex/` artifact path
  2. ✅ modified code path
  3. Resolved active work log path (`.agentcortex/context/work/<worklog-key>.md`)
- `tiny-fix` allows fast-path but MUST provide minimal evidence (diff + one-line verification).

## Legacy State Mapping (Migration)

- `SPEC_READY` -> `SPECIFIED`
- `PLAN_READY` -> `IMPLEMENTABLE`
- `IN_PROGRESS` -> `IMPLEMENTING`
- `UNDER_REVIEW` -> `REVIEWED`
- `DONE` -> `SHIPPED` (Requires test & ship gates)
