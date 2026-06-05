# Work Log: fix/skill-application-wiring

- **Branch**: fix/skill-application-wiring
- **Classification**: quick-win
- **Owner**: KbWen
- **Current Phase**: IMPLEMENT
- **Checkpoint SHA**: 19d33f1
- **Related Spec**: docs/specs/auto-mode-integration.md [Frozen] (follow-up; not unfrozen — see Drift Log)

## Session Info
- Agent: claude-opus-4-8[1m] · Platform: Claude Code (on security-tools) · 2026-06-05

## Goal
Post-ship review of feat/auto-mode-integration found that skill application is unreliable
in unattended Auto-Mode. Root causes:
1. `review.md`'s skill hook gated on `phases:` metadata that NO skill declares, and on
   "During /review:" body sections that don't exist → hook effectively inert.
2. `plan.md` (and most workflows) load zero skills → unattended design ignores skills.
3. Auto-Mode Contract Effect enumerated only §3/§6/§8, omitting the ship-phase confirmation
   → autopilot could stall at /ship.

Constraint (user): simplest reasonable fix; do NOT touch the 17 structurally-inconsistent
skill files (12 dirs + 5 single-file skills); do not amplify problems in an auto-mode repo.

## Approach (minimal, format-native)
- ONE global directive in AGENTS.md §Skill Safety item 4 "Phase-Entry Skill Application":
  every non-tiny-fix phase applies Work Log `Recommended Skills` relevant to the phase,
  relevance judged from the skill `description` (NOT a `phases:` field). Loaded every turn
  → covers plan/implement/review/test/handoff/ship uniformly with zero edits to skill files.
- Fix review.md's broken `phases:` condition + "During /review:" reference.
- Generalize Auto-Mode Contract Effect to cover the ship-phase confirmation.

## Drift Log
- Frozen spec auto-mode-integration.md NOT unfrozen (§4.2 needs user approval). This fix is
  recorded here + Ship History; spec remains accurate (this hardens its AC3/AC4 intent).
- **PREMISE CORRECTION (caught by independent review + self-verification)**: First draft of
  AGENTS.md item 4 asserted "skill stubs may not declare `phases:`" and told agents to NOT
  gate on it. That was FALSE: the 5 domain skills (api-design, auth-security, database-design,
  frontend-patterns, red-team-adversarial — file-based stubs) DO declare `phases:`; only the
  12 process/dir skills lack it. Corrected to a hybrid rule: use `phases:` when present
  (authoritative, do not remove), fall back to `description` only when absent. The reviewer's
  own "16/18 have phases:" count was also wrong (actual 5/17) — verified by direct grep, not
  trusting either side.

## Gate Evidence
- Quick-win: classify → Spec Index checked (auto-mode-integration covers area, frozen) → plan inline → execute → independent review.
- Review gate: independent acx-reviewer (NOT READY — flagged false `phases:` premise) → self-verified ground truth → corrected wording. Fix 3 (ship bullet) rated ✅ correct, no loophole.

## Evidence
- **Ground truth (self-verified)**: `.agent/skills/` — 5 file-skills HAVE `phases:`; 12 dir-skills lack it. AGENTS.md item 4 + review.md now state this accurately.
- **Diff**: AGENTS.md (item 4 + Auto-Mode ship bullet), review.md (Skill-Aware condition). 3 logical changes.
- **Safety**: Auto-Mode ship bullet auto-approves ONLY the ship *confirmation*, gated on `ship Gate pass AND independent review PASS`; all red-line gates intact (reviewer confirmed no loophole).
- **No skill files touched** (per user constraint — avoid amplifying the 17-file structural inconsistency).
- validate.sh: my files clean (only pre-existing test_results.txt BOM, unrelated).
