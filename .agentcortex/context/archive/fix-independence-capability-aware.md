# Work Log: fix/independence-capability-aware

- **Branch**: fix/independence-capability-aware
- **Classification**: quick-win
- **Owner**: KbWen
- **Checkpoint SHA**: bce8820
- **Related Spec**: docs/specs/auto-mode-integration.md [Frozen] (follow-up)

## Session Info
- Agent: claude-opus-4-8[1m] · Claude Code on security-tools · 2026-06-05

## Goal
User flagged a破口: the shipped "independent subagent review" assumed a subagent-spawn
primitive that Antigravity (90% of usage) might not have → would degrade to silent
self-review = false assurance.

## Research (web, 2026-06-05)
- Antigravity **2.0** (shipped 2026-05-19, Google I/O) DOES auto-spawn dynamic/asynchronous
  subagents with isolated context windows ("agents can spawn subagents to parallelize work";
  e.g. auto-splits an audit into a subagent tree per service). CLI preview-quality on Linux.
- Antigravity **1.x**: only MANUAL workspace-level parallel agents (no auto-spawn).
- Claude Code (Task tool), Codex CLI (`/codex-cli`): real isolated dispatch.
- security-tools' own v5 runtime doc (2026-03-04) predates 2.0 → its "single token agent"
  model is outdated.
Sources: medium.com/google-cloud/parallel-agents-in-antigravity, apidog.com/blog/google-antigravity-2,
antigravity.google/docs, ai.google.dev forum.

## Decision
Capability-aware, optimistic default (NOT blanket degrade):
- PRIMARY: dispatch to an isolated-context reviewer (Antigravity 2.0+ subagent / Claude Code
  Task / Codex CLI / ask-openrouter). Supported by all 3 modern primary runtimes.
- FALLBACK (legacy/incapable runtime): clean-slate self-review, marked `independence: degraded`
  — never silent self-approval. Per user (Option 3): degraded MAY still auto-ship but MUST
  carry a loud `⚠️ shipped without independent review` flag (Work Log + ship output).

## Changes
- review.md §Auto-Mode Independence Rule: capability-aware dispatch + degraded fallback.
- AGENTS.md §Auto-Mode Contract item 4 + ship bullet: same, with loud-flag ship behavior.

## Drift Log
- Frozen spec not unfrozen (§4.2). Recorded here + Ship History.
- v5 runtime doc NOT edited (out of scope; it governs gate enforcement, not subagents).

## Gate Evidence
- Quick-win: classify → Spec Index checked (auto-mode-integration, frozen) → execute → independent review.
- Review gate: independent acx-reviewer **PASS** (no required fixes; 2 cosmetic nits applied: degraded-label normalized to `independence: degraded (self-review)`, AGENTS.md cross-ref name normalized). Confirmed: consistent across review.md/AGENTS.md, closes false-assurance gap, degraded-ship weakens NO hard gate (red-line intact, verdict must still PASS), capability claims well-hedged (no GA assertion baked in).

## Evidence
- Diff: review.md (capability-aware dispatch + degraded fallback) + AGENTS.md (item 4 + ship bullet). 2 files.
- validate.sh: clean (only pre-existing test_results.txt BOM, unrelated).
- Safety: degraded mode = honest clean-slate self-review, never silent self-approval; auto-ship allowed but loud-flagged; all red-line gates still binding.
- Research-grounded (Antigravity 2.0 dynamic subagents confirmed via web).
