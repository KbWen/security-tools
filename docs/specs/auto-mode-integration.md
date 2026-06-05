---
feature: auto-mode-integration
status: frozen
owner: KbWen
created: 2026-06-05
classification: feature
---

# Spec: Auto-Mode Integration (Autopilot Hardening)

## Problem

security-tools runs AgentCortex **Runtime v5** plus Antigravity "自動模式" via
`.agent/workflows/autopilot.md`. Autopilot drives the full lifecycle unattended by
**string-matching** the human-confirmation prompts emitted by AGENTS.md §3/§6/§8 and
self-responding "Approved. Proceed." Two structural weaknesses:

1. **Fragile coupling** — if a workflow's confirmation wording changes, autopilot's
   pattern list silently fails to match and the session stalls or mis-proceeds.
2. **Reviewer = implementer (no independent gate)** — autopilot.md §"review" has the
   *same* agent write the code, review it, and self-approve "Yes, commit." In
   unattended mode there is no human in the loop, so this self-grading is the only gate
   between generated code and a commit. That is the single highest-risk hole in 自動模式.

Separately, three owner-defined improvements ride on this change (see ACs).

## Goal

Make 自動模式 **robust and independently-verified** without removing the autopilot
capability, and without weakening any safety gate.

## Non-Goals

- NOT removing human confirmation for non-autopilot (interactive) sessions.
- NOT relaxing Gate / Evidence / Security / Red-Team verdicts. Auto-mode relaxes ONLY
  the *human-confirmation handshake*, never a safety gate.
- NOT a wholesale port of agentic-os runtime; only the targeted pieces below.

## Acceptance Criteria

### AC1 — Native Auto-Mode Contract (replaces string-matching)
- `AGENTS.md` gains a `## Auto-Mode (Autopilot) Contract` section defining:
  - **Activation**: Work Log header field `Mode: autopilot` OR `autopilot.md` loaded.
  - **Effect**: Runtime v5 confirmation handshakes (§3 bootstrap STOP, §6 feature/arch
    confirm, §8 implement confirm) are auto-satisfied → agent proceeds to the next
    phase without waiting.
  - **Invariants (red line, explicit)**: Gates, Evidence (§9), Security verdict,
    Red-Team verdict, and §10 No-Bypass remain hard-enforced. `verdict=fail` still STOPs.
  - **Default**: absent the flag, human confirmation is unchanged.
- `autopilot.md` "Auto-Approval Protocol" is replaced by a one-line reference to the
  AGENTS.md contract (no per-prompt string list).

### AC2 — Independent subagent review in auto-mode
- `review.md` gains an `## Auto-Mode Independence Rule`: when `Mode: autopilot`, `/review`
  MUST be performed by an **independent reviewer in a fresh context** (subagent),
  distinct from the implementing agent — citing `subagent-driven-development` and
  `dispatching-parallel-agents`. Full Red Team (per feature class) is mandatory.
- The "Ready to commit?" verdict in auto-mode requires the **independent reviewer's PASS**;
  the implementing agent MAY NOT self-approve.
- `autopilot.md` review step is updated to dispatch the independent review (not self-approve).

### AC3 — production-readiness skill
- `production-readiness` skill ported from agentic-os: canonical `.agents/skills/production-readiness/SKILL.md`
  (+ `agents/`) and `.agent/skills/production-readiness/` metadata stub.
- Registered for auto-recommend in `bootstrap.md` §3 item 6 (security-tools uses dynamic
  skill discovery, not an enumerated table) and triggered from `review.md` (Error
  Observability Compliance) and `ship.md` (Observability Readiness Check).

### AC4 — Description enrichment for unattended routing
- Workflow frontmatter `description:` and skill metadata `description:` are enriched with
  trigger phrases / whenToUse so intent→phase routing is accurate without a human to
  correct mis-routes. Scope: routing-critical workflows (`review`, `autopilot`, and any
  with a placeholder "Workflow for X" description).

### AC5 — Cross-platform parity
- `CLAUDE.md` gains a one-line pointer to the Auto-Mode Contract.
- `codex/rules` (if it duplicates governance) points back to AGENTS.md, not duplicates.
- Antigravity reads `AGENTS.md` directly (no GEMINI.md in this repo) — canonical section
  is sufficient.

## Risks & Rollback

- **Risk**: a future autopilot session that doesn't set `Mode: autopilot` would fall back
  to interactive confirmation (safe failure — stalls, never auto-proceeds wrongly).
- **Risk**: independent-review dispatch adds tokens/latency. Accepted: it is the core
  safety net for unattended runs.
- **Rollback**: changes are additive doc/governance edits across known files; `git revert`
  of the feature branch restores prior behavior. No code/runtime logic touched.

## Verification

- `grep` confirms each AC's section/field exists in the target file.
- Independent subagent review of the diff (dogfoods AC2).
- `.agentcortex/bin/validate.*` (if present) passes.
