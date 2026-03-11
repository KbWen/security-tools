---
name: handoff
description: Cross-turn handoff summary & hard reference checks.
tasks:
  - handoff
---

# /handoff

Read-only logic. DOES NOT change state. Hard completion gate for non-`tiny-fix` tasks.

> Canonical gate: `Ref: .agent/rules/state_machine.md`

## 1. Trigger Conditions

- Non-`tiny-fix`, Non-`quick-win`: MUST execute before pause, end, or handoff. AI should remind the user if this step is missing (see §10.6 Completion Guard).
- `quick-win`: Exempt from formal handoff, but AI SHOULD offer a brief `/retro`.
- `tiny-fix`: Exempt, but MUST retain minimal evidence.

## 2. Platform Specialization

- **Codex Web**: MUST output full summary directly in chat.
- **Antigravity / Codex App**: Auto-write to `docs/context/work/<worklog-key>.md`.
- If the active Work Log is missing, resolve or create the current `<worklog-key>` log first. If the previous log was archived after a prior ship, create a follow-up active log and note that recovery in the delta.

## 3. Required Output Blocks

- **Layer 1 (Handoff TL;DR, <= 10 lines)**:
  - Goal
  - Current State
  - Next Action
  - Blocker (or `none`)
  - Owner
  - Last Verified Command
- **Layer 2 (Traceability)**:
  - Done
  - In Progress
  - Blockers
  - Next
  - Risks
  - References
- **Resume Block**: MUST also write the following to the Work Log file:

```markdown
## Resume
- State: [current state machine state]
- Completed: [list of done steps]
- Next: [immediate next action]
- Context: [1-2 sentence summary of what was decided and why]
```

## 4. Minimum References (HARD GATE)

MUST include ALL of the following:

1. At least 1 docs/ file path
2. At least 1 code file path
3. Corresponding Work Log path (`docs/context/work/<worklog-key>.md`)

If requirements unsatisfied, COMPLETION AND `/ship` ARE STRICTLY PROHIBITED.

## 5. Work Log Writing Rule (Delta-Only)

- Append only what changed in this turn (delta log).
- DO NOT restate old background unless it is required for a decision or rollback.
- If context repeats, link to the previous section instead of re-writing full paragraphs.

## 6. Work Log Compaction Trigger (Portable Defaults)

If either threshold is hit:

- `WORKLOG_MAX_LINES` (default: `300`), or
- `WORKLOG_MAX_KB` (default: `12`)

MUST compact the Work Log:

1. Keep `## Session Info`, latest `## Resume`, latest `## Risks`, and the latest `N` delta entries (`WORKLOG_KEEP_RECENT_ENTRIES`, default: `5`).
2. Move older details to `docs/context/archive/work/<worklog-key>-<YYYYMMDD>.md`.
3. Add one line in current log: `Compacted: [date], archive: [path]`.

## 7. Token & Efficiency Reflection

If task was abnormally long or consumed high tokens, briefly explain why (e.g., "ambiguous specs", "bug loop"). Aids in continuous governance optimization.
