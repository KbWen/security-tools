---
name: ship
description: Final delivery and archival. Requires TESTED state and handoff gate.
tasks:
  - ship
---

# /ship

> Canonical gate: `Ref: .agent/rules/state_machine.md`

## Gate Engine (Turn 1 — Antigravity Hard Path)

Before ANY ship action, output the Minimal Gate Block:

```yaml
gate: ship
classification: <from Work Log>
branch: <current branch>
checks:
  worklog_exists: yes|no
  spec_exists: yes|no|na
  state_ok: yes|no
  handoff_ok: yes|no|na
verdict: pass|fail
missing: []
```

- If `verdict: fail` → output ONLY the gate block. STOP.
- Resolve the active Work Log path for the current `<worklog-key>` before evaluating `worklog_exists`.
- If no active Work Log exists but archive context for the branch exists, create a follow-up active log, warn the user, and continue gate evaluation. Missing handoff references or missing evidence still require `verdict: fail`.
- If classification is `feature` or `architecture-change`:
  - Output: "Gate passed. Awaiting your confirmation to proceed with shipping."
  - STOP until user replies affirmatively.
- `quick-win` / `hotfix`: proceed directly after gate pass.

## Work Log Compaction Check

Before ship evaluation, check the active Work Log size. If it exceeds compaction thresholds (see `.agent/config.yaml` §worklog), compact per `/handoff` §6 BEFORE proceeding. Ship with a bloated log risks archiving an unnecessarily large file.

## Entry Conditions (HARD)

1. Current state is `TESTED`.
2. Non-`tiny-fix` tasks MUST have completed `/handoff`.
3. `/handoff` References MUST meet minimums (doc + code + work log).
4. **Security Gate**: No unresolved CRITICAL/HIGH security findings in Work Log (per `.agent/rules/security_guardrails.md` §6). If found, `verdict: fail`, `missing: ["security: N unresolved CRITICAL/HIGH findings"]`.

If ANY condition fails, MUST reject `/ship` and output missing list.

## Output Format

- Commit message (Conventional Commits)
- Change summary (bullet points)
- Test results (Evidence)
- Doc sync status (Did `current_state.md` update?)
- Known risks and rollback strategy

## State Update & Archival

1. **Ship Guard (§11.3)**: Before writing, check if `current_state.md` has been modified since this task started. If modified by another session, warn user and request confirmation before merging. Use **additive merge**, never full overwrite.
2. **SSoT Update & Ship History**:
   - Update `.agentcortex/context/current_state.md` Spec Index statuses (mutable snapshot).
   - MUST append the completion record to the bottom of the file under `## Ship History`.
   - Use the format:

     ```markdown
     ### Ship-<branch_name>-<YYYY-MM-DD>
     - Feature shipped: [summary]
     - Tests: Pass
     ```

   - NEVER edit, reorder, or delete previous entries in the `## Ship History`.
   - If Ship History exceeds 10 entries, archive older entries to `.agentcortex/context/archive/ship-history-YYYY.md` and keep only the latest 10 in `current_state.md`.
3. Archive `.agentcortex/context/work/<worklog-key>.md` to `.agentcortex/context/archive/` (if task complete).
    - Before archiving: Extract ALL bullets from the Work Log's `## Lessons` block (max 3 total).
    - Append these bullets to the `## Global Lessons` section in `current_state.md`.
    - If there is no `## Global Lessons` section in `current_state.md`, create one at the bottom.
    - **Archive Index Update**: After archiving, append entries to `.agentcortex/context/archive/INDEX.md`:
      - `By Module`: list each modified file/module → archived log filename + key decision
      - `By Pattern`: tag with reusable patterns (e.g., `[windows-compat]`, `[namespace-migration]`)
      - `By Decision`: extract key decisions from `## Decisions` section (if present)
      - Keep each entry to 1 line. If INDEX.md does not exist, create it with the standard header.
4. **Product Backlog Update**: If `.agentcortex/specs/_product-backlog.md` exists and this feature is listed:
   - Update feature status: `In Progress` → `Shipped`
   - Update `last_updated` in frontmatter
   - If ALL features are now `Shipped` or `Deferred`/`Cancelled`, output: "🎉 Product backlog complete. All features shipped or resolved."
   - If Pending features remain, output: "Backlog: [N] features remaining. Next session can run `/spec-intake` §8a to continue."
   - Update `current_state.md` **Active Backlog** field to `.agentcortex/specs/_product-backlog.md` (if not already set). This is the only mechanism that persists backlog awareness across sessions via SSoT.
5. Freeze Artifacts: Ensure all produced Specs/ADRs have YAML frontmatter `status: frozen`. If missing, add it before commit.
   - **Skip non-freezable statuses**: Documents with `status: living` (e.g., `_product-backlog.md`) or `status: raw` (e.g., `_raw-intake.md`) MUST NOT be frozen. These are tracking/temporary artifacts, not spec deliverables.
   - **Spec Freshness**: If implementation DIFFERS from any referenced spec's AC, MUST update the spec to match actual behavior before freezing. Append `[Updated: <date>]` to the corresponding Spec Index entry in `current_state.md`.
