---
description: Workflow for implement
---
# /implement

> Hard Gate: state >= `IMPLEMENTABLE` (Plan quality gate MUST be passed).

## Handshake (Turn 1 — feature / architecture-change only)

For `feature` or `architecture-change` classification:

- Output: "Gate passed. Awaiting your confirmation to proceed with implementation."
- STOP until user replies affirmatively.
- When user replies to proceed, cite Work Log plan section (path + heading) before writing any code.

`quick-win` / `hotfix`: proceed directly (no handshake).

## Work Log Compaction Check

Before implementation, check the active Work Log size. If it exceeds compaction thresholds (see `.agent/config.yaml` §worklog), compact per `/handoff` §6 BEFORE proceeding. This prevents bloated logs from inflating token costs during the implementation phase.

## Pre-Execution Check (Mandatory)

Before ANY code change, AI MUST:

1. Read the `## Non-goals` section of the Spec referenced in this task's Work Log.
2. Confirm the current implementation step does NOT touch any Non-goal item.
3. If a step would require touching a Non-goal, STOP and surface: "⚠️ Step [N] conflicts with Non-goal: [item]. Proceed? (yes/no)"
4. IF Work Log contains a `Recommended Skills` entry: READ those SKILL.md files now before writing any code.
   - Explicitly state: "Applying [skill-name] strategy for this implementation."
5. Read the `## Acceptance Criteria` section of the referenced Spec (if `feature` or `architecture-change`).
6. For each implementation step, verify it maps to at least one AC or is a necessary supporting change.

Execute the approved plan. STRICTLY restricted to modifying ONLY the listed target files.

## Mid-Execution Guard

- **Classification Escalation**: If actual changes exceed the classification threshold (e.g., `quick-win` touching >2 modules or adding new directories), AI MUST pause and remind: "⚠️ Scope has grown beyond `[current-tier]`. Recommend escalating to `[higher-tier]` to activate Spec/Handoff gates. Escalate? (yes/no)"

## Post-Execution Report

- Summary of actual changes
- Potential side-effects
- Suggested verification/test commands
- **Scope Divergence Check**: Compare actual modified files against planned target files. If extra files were touched, flag: "⚠️ Scope divergence: planned [N] files, touched [M] files. Extra: [list]. Confirm these are intentional? (yes/revert)"

## Security Quick-Scan (Auto — No User Action Required)

After implementation, AI MUST run `.agent/rules/security_guardrails.md` Always-On checks (§1 A01–A03) + Secret Detection (§3) on all files touched in this implementation step.

- If **CRITICAL/HIGH** findings: append to Post-Execution Report and flag: "🔒 Security issue found — MUST resolve before `/review`."
- If **MEDIUM/LOW** findings: append to Post-Execution Report as informational.
- This is a lightweight pre-screen. Full security scan runs during `/review`.
