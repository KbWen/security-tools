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

### AC2 — Capability-aware independent review in auto-mode *(amended 2026-06-05 — see note)*
- `review.md` gains an `## Auto-Mode Independence Rule`. **Honest default**: no current runtime
  (Claude Code / Codex / Antigravity 2.0) reliably auto-dispatches an isolated reviewer
  *unattended by default*, so a **marked clean-slate self-review**
  (`independence: degraded (self-review)`) is the DEFAULT path. True isolated-subagent review
  is an explicit per-platform **opt-in** (Antigravity `start_subagent`/`/teamwork-preview`;
  Claude Code explicit Agent/Task or hook; Codex `codex exec`; `/ask-openrouter`). Full Red
  Team (per feature class) is mandatory.
- The "Ready to commit?" verdict requires PASS; **independence counts only with proof**
  (configured mechanism + distinct executor identity), never because a runtime "supports"
  subagents or a skill "might" have auto-activated. The ship output carries the
  `⚠️ shipped without independent review` flag **BY DEFAULT**, suppressed only on that proof.
- `autopilot.md` review step reflects the default-degraded + flag behavior.

> **Amendment note (2026-06-05, owner-approved unfreeze→amend→refreeze)**: the original AC2
> mandated "independent subagent review … requires the independent reviewer's PASS"
> unconditionally. Per-platform capability research (3 research + 3 expert agents; commit
> `950e4e8`) found NO runtime reliably auto-dispatches an isolated reviewer unattended by
> default, making that mandate a false-assurance. AC2 now reflects the honest default
> (degraded self-review default + opt-in isolation + default-on ship flag). Implementation
> in `AGENTS.md` §Auto-Mode Contract, `review.md`, `autopilot.md`.

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
