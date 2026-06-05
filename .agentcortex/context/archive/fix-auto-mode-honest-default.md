# Work Log: fix/auto-mode-honest-default

- **Branch**: fix/auto-mode-honest-default
- **Classification**: quick-win (corrections to shipped auto-mode governance + tooling)
- **Owner**: KbWen
- **Checkpoint SHA**: 68c301f
- **Related Spec**: docs/specs/auto-mode-integration.md [Frozen]

## Session Info
- Agent: claude-opus-4-8[1m] · Claude Code on security-tools · 2026-06-05

## Goal
Per user: confirm each platform's real subagent + skill capability BEFORE modifying, then
research + expert panel + final review. Three parallel research agents + three expert agents
converged on corrections to the auto-mode governance I shipped earlier.

## Capability matrix (researched, June 2026)
- Subagent auto-dispatch (isolated, unattended, BY DEFAULT): **NONE of Claude Code / Codex /
  Antigravity 2.0 reliably does this by default.** Claude = model-discretion (hooks for
  determinism); Codex = "only spawns when explicitly asked" (or `codex exec`); Antigravity
  2.0 = `start_subagent` needs CapabilitiesConfig + teamwork is Ultra-only research preview.
- Skill auto-activation: native on all three but **probabilistic (model-discretion** from
  `description`), per-skill suppressible. Not a deterministic gate.

## Corrections (6)
1. **production-readiness 1:1 fix**: `.agent/skills/production-readiness/SKILL.md` was a 14-line
   stub vs 82-line `.agents/` body → Antigravity (90% platform) saw a gutted skill. Copied full
   body (now 82=82, matches all other dir-skills).
2. **AGENTS.md item 4 reframe**: degraded clean-slate self-review is the HONEST DEFAULT (not a
   legacy-1.x fallback); true isolated review is an explicit per-platform opt-in; independence
   counts only with proof (mechanism + executor), never from "runtime supports it" or a skill
   that "might" have activated.
3. **AGENTS.md ship bullet FLIP** (most important — gap C): `⚠️ shipped without independent
   review` flag is now **default-ON, suppressed only on affirmative proof** of configured
   independence. (Was: flag only if review self-reported degraded — trusting the unreliable
   path to confess its own failure.)
4. **review.md §Independence Rule**: restructured default-first; admits player/referee
   separation does NOT hold in default; description frontmatter de-overstated.
5. **autopilot.md** (the driver): same default-degraded + flag language; no longer mandates
   unavailable independence (closes gap B — driver overriding the honest contract).
6. **validate.sh + validate.ps1**: added byte-level 1:1 sync check for directory-form skills
   (was skipped entirely — `-f`/`-File` skips dirs, no content diff). This is the gap that let
   defect #1 ship. Verified: EXIT 0 when 1:1, EXIT 1 on induced divergence.

## Drift Log
- Frozen spec not unfrozen (§4.2). Recorded here + Ship History.
- Capability matrix corrects my EARLIER (71aa452) over-optimistic "Antigravity 2.0 auto-spawns →
  use it as primary" framing. 2.0 CAN, but not by default/unattended → degraded is the honest default.

## Gate Evidence
- Quick-win: classify → Spec Index checked → execute → independent review.
- Research: 3 parallel research agents (Claude/Codex/Antigravity) + 3 expert agents (platform
  accuracy / governance honesty / downstream deployment) — all converged.
- validate.sh: **pre-existing EXIT 1** from `test_results.txt: utf8-bom` (tracked stray
  artifact; FAILS on `main` too — verified by checking out main). NOT caused by this change.
  My new skill 1:1-sync check PASSES (production-readiness now 82=82 IDENTICAL); verified it
  fires (EXIT 1) on induced divergence and passes (EXIT 0 portion) when in sync.

## Evidence
- **Honesty correction**: earlier ship evidence (commits 19d33f1/c3a6d70/71aa452) claimed
  "validate clean" — that was WRONG; I had masked the exit code with `| tail`. validate.sh has
  been EXIT 1 on `main` all along due to the pre-existing `test_results.txt` BOM. My changes do
  not affect it. To be flagged for separate cleanup (do not delete the tracked file unilaterally).
- GhostCheck pre-commit: expected Grade A (governance/tooling docs; no code).
- 3 research agents + 3 expert agents converged on exactly these 6 corrections.
- (final independent review pending)
