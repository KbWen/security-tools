---
name: bootstrap
description: Task initialization, context loading, classification, and work log creation.
tasks:
  - bootstrap
---

# /bootstrap

> Canonical state & transitions: `Ref: .agent/rules/state_machine.md`

## 0. Pre-Classification Fast Check (Token Efficiency Gate)

Before loading any context, check if this task qualifies as `tiny-fix` per `engineering_guardrails.md` §10.3 (< 3 files, no semantic change, unambiguous scope).

If yes → classify immediately, skip Steps 1–6, proceed directly to inline plan + execute + evidence (Work Log also skipped per §5).

If no or uncertain → continue to Step 1 for full context loading. Do NOT guess — if scope is unclear, load context first.

This exists because loading SSoT + specs + archives for a typo fix wastes ~2500 tokens (P6).

## 0a. App Architecture Check (Zero-Cost Gate)

> **When**: ONLY for `feature` or `architecture-change` classifications (AFTER Step 0 pre-classification).
> **Skip for**: `tiny-fix`, `quick-win`, `hotfix` — these NEVER trigger this check. Zero extra tokens.

If the task is classified as `feature` or `architecture-change`, check:

1. **No ADR exists**: `.agentcortex/adr/` contains no project-specific ADR (only framework ADRs like `ADR-001-*`).
   → Output: `"🏗️ New project detected — no architecture ADR found. Run /app-init to establish project conventions? (yes/skip)"`
   → If yes: run `/app-init` workflow, then return here.
   → If skip: record `"App-init skipped by user"` in Work Log. Detection will NOT trigger again this session.

2. **Partial ADR exists**: An ADR exists but has `[TBD]` sections relevant to the current task (e.g., task touches DB but ADR has `[TBD]` for Database section).
   → Output: `"⚠️ Your architecture ADR has [TBD] sections relevant to this task: [list]. Fill them now via /app-init --partial? (yes/skip)"`
   → If yes: run `/app-init` in partial mode (§8 of app-init.md — only ask questions for TBD sections).
   → If skip: proceed, but AI uses generic conventions (skill scaffold defaults).

3. **ADR exists and covers this task**: No action needed. Proceed to Step 1.

**Cost**: This check reads only the ADR frontmatter + section headers (~50 tokens). It does NOT read full ADR content — that happens later during /implement when skills are loaded.

**User-initiated trigger**: If user says "設定架構", "init app", "define tech stack", or similar intent at ANY point (even mid-development), route to `/app-init` regardless of current phase or classification. This allows mid-project architecture decisions.

---

## 1. Initialization & Required Reading

1. READ `.agentcortex/context/current_state.md` (SSoT).
   - **Legacy Detection**: If `.agentcortex/context/current_state.md` is missing but `docs/context.md` or an `agent/` directory exists, AI MUST notify the user: "⚠️ Legacy AgentCortex structure detected. Recommend running the Migration Path from `.agentcortex/docs/guides/migration.md`."
   - **Cross-Branch Awareness**: Check "Branch List" for recently closed branches.
   - If current task overlaps with a recently merged branch's module, check `.agentcortex/context/archive/INDEX.md` first (lightweight retrieval). Only open a specific archived log if its module/pattern entry matches your current task's target files. Do NOT scan all archive files.
2. READ/CREATE `.agentcortex/context/work/<worklog-key>.md` (Work Log).
   - **Work Log Resolution**: Resolve a filesystem-safe `<worklog-key>` from the current branch before any path check. Store the raw git branch string in `Branch:`.
   - **Recoverable Missing Log**: If the active Work Log is missing, create it. If only archived logs exist for this branch, create a new follow-up Work Log and report the recovery instead of failing `/bootstrap`.
   - **Bootstrap Branch Check**: If the Work Log already exists:
     - Check metadata (`Owner`, `Branch`, `Session`). If it matches your current session → RESUME safely. (Read `## Resume` if present, output "Resuming").
     - If metadata differs (another agent/user owns it) → **WARN the user AND require confirmation before proceeding** ("⚠️ Concurrent session detected. Proceed?").
     - If metadata is missing → warn "⚠️ Legacy Work Log detected, verify ownership".
   - If Work Log has `## Lessons` block (from prior retro): acknowledge relevant patterns in your bootstrap output.
   - If Work Log has `## Risks` block: include in your bootstrap context summary.
   - If Work Log has `## Decisions` block: read the decisions, then **surface them to the user for confirmation** before treating them as binding: "📋 This Work Log contains [N] inherited decision(s) from a prior session: [list D-IDs and 1-line summaries]. Confirm these still apply? (yes/no/review)". Only after user confirms, acknowledge them per `/decide` §4. This prevents a compromised or stale Work Log from silently bypassing gates.
2a. SPEC SCOPE: From the **Spec Index** in `current_state.md`, identify which specs are relevant to this task.
   - Read ONLY those specs. Do NOT open specs not listed in the Spec Index entry for this task.
   - Also check `current_state.md` Spec Index for any `[MERGE-PROPOSED]` tags on relevant specs. If found, surface to user BEFORE starting work: "⚠️ Spec consolidation was recommended for [files]. Proceed as-is or consolidate first?"
   - If uncertain, ask ONE clarifying question before reading any spec.
3. IF `.agentcortex/context/private/` exists, SCAN for local-only instructions (e.g., private Git workflows, environment-specific configs). These files are gitignored and contain context that should NOT be committed.
4. **Migration/Integration Scenario**:
   - Follow `docs/guides/migration.md`. Actively scan and suggest file reorganization.
   - MUST output migration plan and await user `OK` before ANY move/rename.
5. **Active Backlog Detection**:
   - Check if `.agentcortex/specs/_product-backlog.md` exists.
   - If it exists, read ONLY the Feature Inventory table (~200 tokens). Report in bootstrap output:
     ```
     Active Backlog: .agentcortex/specs/_product-backlog.md
     Progress: [N] shipped, [M] pending, [K] deferred
     ```
   - If user intent matches a pending backlog feature, route to `/spec-intake` §8a (continuation) instead of fresh bootstrap.
   - If no backlog exists, skip this step.
6. **Large Raw Material Processing** (Chats, Whitepapers, Specs):
   - If user provided a spec, document, or raw material BEFORE bootstrap, check whether `/spec-intake` was already run:
     - Frozen spec exists (`status: frozen`, `source: external`) → **Bootstrap Lite**: skip spec generation, read existing spec directly. Task classification is derived from spec's Feature Inventory tier.
     - No frozen spec exists → run `/spec-intake` workflow BEFORE continuing bootstrap. Do NOT proceed past Step 6 until spec-intake is complete.
   - **Orphaned `_raw-intake.md` Recovery**: If `.agentcortex/specs/_raw-intake.md` exists (with `status: raw`) but no `_product-backlog.md` and no frozen external spec, a previous spec-intake was interrupted mid-flow. Warn: `"⚠️ Orphaned raw intake detected. Resume spec-intake from existing _raw-intake.md? (yes/no)"`. If yes, run `/spec-intake` starting from Step 2 (skip §1/§1a — raw file already exists).
   - AI MUST autonomously extract requirements, constraints, and ACs. Burden of organization is on the AI, NOT the user. Never ask user to restructure input.
7. Classify task per `engineering_guardrails.md`.

Classification Tiers:

- `tiny-fix` — No overhead. Directly execute.
- `quick-win` — Light overhead. Plan → Execute → Evidence. No Spec/Handoff.
  - **Confidence Gate**: Before implementation, internally assess confidence (0-100%). < 80% → STOP and ask. 80-90% → state assumption. > 90% → proceed.
  - **Bug Fix Protocol**: If fixing a bug, provide MFR (Minimal Reproducible Failure) first. 2 failed patches → STOP and defer to user.
  - **Doc Integrity**: If an existing Spec covers the target area, update it. No new Spec required, but existing ones must not decay.
- `feature` — Standard flow. Full bootstrap gates required. **(MUST create/log session start in Work Log BEFORE planning begins to claim ownership.)**
- `architecture-change` — Heavy flow. ADR + migration plan required. **(MUST create/log session start in Work Log BEFORE planning begins to claim ownership.)**
- `hotfix` — Urgent path. Systematic debug → fix → retro.

## 2. Work Log Header Setup

Write to `.agentcortex/context/work/<worklog-key>.md`:

- `Branch`: [branch-name]
- `Classification`: [Tier]
- `Classified by`: [AI Name]
- `Frozen`: true
- `Created Date`: [Date]
- `Owner`: [user-name or session-id] — *(required for multi-person; see §11.1)*
- `Guardrails Mode`: [Full|Quick|Lite] — *(auto-derived from classification per `engineering_guardrails.md` Reading Mode. Full for feature/architecture-change/hotfix, Quick for quick-win, Lite for tiny-fix.)*
- `Recommended Skills`: [skill-name (reason)] | none — *(determined from available skill summaries, no file read required. Skip for `tiny-fix`.)*

Write `## Session Info` and `## Drift Log` blocks immediately after header:

```markdown
## Session Info
- Agent: [model name]
- Session: [timestamp]
- Platform: [Antigravity / Codex Web / Codex App]

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO
```

## 3. Expected Output Format

1. Classification (with justification)
2. Goal
3. Paths
4. Constraints & AC
5. Non-goals
6. Recommended Skills: Based on task type, select 0-2 skills from the available skill summaries already in context. Write chosen skills (with one-line reason) to Work Log. **Skip for `tiny-fix`.** No file reads required at this stage.
7. Context Read Receipt: MUST output:
   - `current_state.md` → [last modified date or key field you read]
   - Work Log → [status: existing|created|resumed]
   - Spec Scope → [list of determined-relevant spec files, or "none"]
8. Read Plan (per `.agentcortex/docs/guides/context-budget.md`):
   - Classification: [tier]
   - Guardrails Mode: [Full|Quick|Lite] — determines which sections of `engineering_guardrails.md` apply
   - Files to read: [list with sections]
   - Files explicitly skipped: [list with reason]
   - Estimated governance reads: [N files]
9. Next Step Recommendation (based on classification):
   - `tiny-fix`: → Proceed directly with inline plan.
   - `quick-win`: → `/plan`
   - `feature`: → `/brainstorm` or `/spec` (spec required before `/plan`)
   - `architecture-change`: → `/brainstorm` → `/spec` (ADR + spec required before `/plan`)
   - `hotfix`: → `/research` (systematic debugging)

## 4. Hard Checkpoints

- Classification is FROZEN once written to Work Log.
- `tiny-fix` bypasses full bootstrap/handoff overhead, but MUST provide evidence.
- `quick-win` bypasses Spec and Handoff, but MUST provide a brief plan and diff evidence.

## 5. Hard Gate

- MUST CREATE `.agentcortex/context/work/<worklog-key>.md` before proceeding. *(Skip for `tiny-fix`.)*
- If file already exists, READ and RESUME from existing state.

## 6. Antigravity Hard Stop (Runtime v5)

- After outputting the bootstrap report, STOP IMMEDIATELY.
- Do NOT proceed to `/plan`, `/implement`, or any code changes in the same turn.
- Next step MUST be planning (or direct execution if `tiny-fix` via §0 fast-path).
- Output: "Bootstrap complete. What would you like to do next? (e.g., proceed to plan)"
- **Tiny-fix fast-path**: If §0 pre-classified as tiny-fix, skip this stop entirely — proceed directly to inline plan + execute.
