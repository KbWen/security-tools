# Engineering Guardrails (Constitution)

## Scope

Global (applies to all projects using template).

## Reading Mode

- **Full Mode** (default for `feature`, `architecture-change`, `hotfix`): Read this entire document.
- **Quick Mode** (for `quick-win`): Read ONLY: §4 (Design Before Implementation), §7 (Scope Discipline), §8.1 (Bug Fix Protocol if applicable), §9.1 (Acknowledgment-only Inputs). Skip §1-3, §5-6, §10.1-10.2.
- **Lite Mode** (for `tiny-fix` ONLY): Read ONLY the following sections:
  - §7 Scope Discipline (mandatory)
  - §8.1 Bug Fix Protocol (if fixing a bug)
  - §9.1 Acknowledgment-only Inputs (always)
  - §10.3 Tiny-Fix Fast-Path (for verification)
  - Skip sections 1-4, 6, 10.1-10.2. These do not apply to tiny-fix tasks.

## Role

Non-negotiable principles for agent-driven development.

## 1. Core Philosophy

### 1.1 Correctness First

- Correctness > Performance/Complexity/Features.
- Unverifiable behavior is classified as UNSAFE.

### 1.2 Explicit Over Implicit

- Assumptions, preconditions, limitations MUST be explicitly stated.
- Implicit magic behavior is PROHIBITED.

### 1.3 Reproducibility by Default

- Same input MUST yield same output.
- Randomness MUST be controllable, toggleable, and traceable.

## 2. Change Safety Principles

### 2.1 Small & Reversible Changes

- Micro-patches preferred.
- Rollback MUST be designed upfront.

### 2.2 Preserve Existing Behavior

- DO NOT alter existing semantics unless explicitly requested.
- New behavior MUST be feature-flagged or config-driven.

## 3. Data & Time Integrity

- Look-ahead bias PROHIBITED.
- Exact temporal ordering MUST be stated.
- Input -> Output causality MUST be clear.

## 4. Design Before Implementation

- BEFORE coding, MUST provide: Problem understanding, Design, Trade-offs, Risks.
- If ambiguous, priority is CLARIFICATION.

### 4.1 Spec Freezing (SSoT Protection)

- Whenever a Spec is approved or the task transitions to implementation, the Spec MUST be marked as **FROZEN** (e.g., via YAML frontmatter `status: frozen`).
- AI agents MUST NOT modify, review, or suggest refactoring for any document marked as `FROZEN` or `Finalized` during normal tasks.
- **Exception (AI-Initiated Unfreeze)**: If the AI discovers that a FROZEN spec must be changed (due to a bug or requirement change), the AI MUST:
  1. **STOP** and surface the issue explicitly: "⚠️ [Filename] is FROZEN but requires update: [Reason]. Approve to unfreeze and continue? (yes/no)"
  2. Only proceed after user responds **YES**.
  3. Set status to `draft`, make changes, then re-freeze during `/ship`.

## 5. Testing & Verification

- Logic Change -> Add Test.
- Interface Change -> Verify Compatibility.
- **Sanity Check**: Is output bounding safe? Side-effects?
- **Doc-First Pillar**: Architecture/Core logic changes MUST precede with Spec/ADR in `docs/`.
- **Naming/Locations**:
  - ADRs: `docs/adr/ADR-[ID]-[kebab-case].md`
  - Specs: `docs/specs/[feature-name].md`
  - Guides: `docs/guides/[topic].md`
  - Agent Work Logs: `docs/context/work/`
  - Private Context: `docs/context/private/` (local-only, gitignored)
    - USE FOR: personal dev environment configs, private remote URLs, internal credentials references, team-specific workflows not intended for public repos.
    - DO NOT USE FOR: project architecture docs, contribution guides, public development standards.
    - WHEN UNCERTAIN: Agent MUST present options to user in `/plan` phase. Autonomous path decisions on ambiguous content are PROHIBITED.

## 6. Explainability & Traceability

- Big decisions MUST be traceable ("Why was this done?").
- Intermediate results and Decision Traces prioritized.

## 7. Scope Discipline

- ONLY solve requested issue. UNAUTHORIZED REFACTORING IS PROHIBITED.
- If larger issue discovered, output a "Follow-up Issue" recommendation.

## 8. Agent Operating Mode

- **Default**: Conservative, Explainable, Stable.
- **When Uncertain**: State ambiguity, provide 2-3 options, DEFER high-impact decisions to user.

### 8.1 Bug Fix Protocol

**MFR (Minimal Reproducible Failure)**: BEFORE any fix, MUST provide:

- Repro steps (≤3 steps), Expected vs. Actual behavior.

**2-Strike ESC**: If the SAME issue fails after 2 patches:

1. STOP patching immediately.
2. Output diagnostic: modified code blocks, call relationships, behavior diffs ONLY. ❌ No narrative claims.
3. Record failure in Work Log and DEFER to user for escalation.

**Active Tracking**: After each failed patch attempt, AI MUST append to Work Log: `Patch Attempt [N]: [1-line result]`. When N ≥ 2, the 2-Strike ESC is automatically triggered.

**Async/Data-Flow Safety**: When modifying async or data-flow code, MUST verify: error handling, race condition guards, and loading state management.

### 8.2 External Tool Delegation Protocol

External CLI tools (e.g., `ask-openrouter`, `codex`) are **OPTIONAL accelerators**. Projects MAY operate without any of them.

**Pre/Post-Flight (Mandatory for all external tool invocations)**:

- **Pre-Flight** (in order — fail fast):
  1. **Cost-Tier Confirmation** (memory-only): low-cost → auto-execute; high-cost (quality/max profile) → confirm with user first.
  2. Update Work Log with `Executor: <tool-name>` (only if cost-tier passes).
  3. **Availability Check (Silent)**: run health check (e.g., `python -m ask_openrouter --help`, `codex --version`). If unavailable: **silently fall back** to AI-native execution. DO NOT warn user. DO NOT suggest installation. Cache per session.
- **Post-Flight**: Read tool output, verify scope alignment, update Work Log, apply Gate Check per §10.2.
- External tool output is treated as **Junior Tool output** — AI MUST review before accepting.

## 9. Intent Safety Rules

User input in any form (natural language, keywords, or slash commands) triggers the same workflow gates. AI determines the current phase and enforces prerequisites automatically. Slash commands are optional shortcuts, not required triggers.

### 9.1 Acknowledgment-only Inputs (No Action)

The following inputs MUST NOT trigger any state transition or execution:

- EN: "OK", "Sure", "Got it", "Alright", "Fine"
- ZH: "好", "收到", "嗯", "了解", "沒問題"

Correct behavior: Confirm receipt, optionally ask what the next step should be.

### 9.2 Vague Inputs (Must Clarify)

Inputs without a clear action verb or direction MUST prompt a clarification question:

- EN: "fix it", "tweak something", "make it better", "adjust this"
- ZH: "弄一下", "調整一下", "改改看", "處理一下"

NEVER guess intent. NEVER proceed on vague input.

### 9.3 Search Policy (Lexical-first)

When locating code, files, or definitions:

1. ALWAYS use lexical search first (ripgrep, path lookup, directory listing).
2. Semantic search is allowed ONLY after lexical search yields no results.
3. If still unresolved, ask a targeted question.

### 9.4 Core Principle
>
> When intent is unclear, ASK. Never guess. Never proceed.

## 10. vNext Governance & Classification

### 10.1 Escalation Rules

| Trigger Condition | Minimum Classification |
| --- | --- |
| < 3 files, no semantic change | `tiny-fix` |
| 1-2 modules, clear scope, no cross-module impact | `quick-win` |
| Touches `exports` / public API / signature | `feature` |
| Touches >1 module import graph | `feature` |
| Adds new directories | `feature` |
| Alters data-flow / system boundaries | `architecture-change` |
| Alters default configs impacting users | `feature` |

### 10.2 Gate Type & Evidence Standards

| Category | Mandatory Gates | Min Evidence Required |
| --- | --- | --- |
| **tiny-fix** | classify → plan (inline) → execute | diff summary + 1-line verification |
| **quick-win** | classify → check Spec Index → plan → execute → evidence | diff + before/after behavior statement |
| **feature** | bootstrap → spec → plan → review → test → handoff | test output + verifiable demo steps |
| **architecture-change** | bootstrap → ADR → spec → plan → migration/rollback → handoff | migration plan + rollback verification |
| **hotfix** | systematic debug → evidence → fix → retro → handoff | root cause + fix verification + retro |

AI self-enforces the phase order above. Users may invoke phases via slash commands (as shortcuts) or natural language.

### 10.3 Tiny-Fix Fast-Path

- **Definition**: Modifies < 3 files WITHOUT semantic change (typo, docs, non-functional config).
- **Flow**: `classify → one-line scope → execute → inline evidence → done`.
- **Exclusion**: Bypasses full bootstrap, handoff, and Work Log overhead.

### 10.4 Quick-Win Fast-Path

- **Definition**: Clear, contained change to 1-2 modules with a well-defined outcome. Semantic change IS present, but cross-module impact is LOW.
- **Flow**: `classify → check Spec Index for existing coverage → plan (brief) → execute → update existing Spec if found → inline evidence → done`.
- **Exclusion**: No formal Spec required. No `/handoff` required. Work Log entry optional but recommended.
- **Doc Integrity (MANDATORY)**: While No *new* Spec is required, if an **existing** Spec already covers the target area, the AI MUST update that Spec to prevent "Documentation Decay." If the change is too complex for a stealth update, use the "Spec Seed" mechanism in `/retro` to flag it for formalization.
- **Examples**: Changing an API response format, adding a config flag, fixing a single-module bug with known root cause.

### 10.5 Handoff/Ship Hard Gate

- Non-`tiny-fix` tasks MUST NOT claim complete without a handoff phase.
- The ship phase MUST verify handoff references in single-line format: `ship:[doc=<path>][code=<path>][log=<path>]`
- If any field is missing, AI MUST reject shipping and list the missing field(s).

### 10.6 Completion Guard (Anti-Silent-Exit)

When AI detects a task is nearing completion (e.g., user says "done", "完成了", "差不多了", or AI has finished all planned steps), AI MUST self-check BEFORE responding:

1. Is the task classified as `quick-win` or higher?
2. Has the handoff phase been executed? (Check: does Work Log have a `## Resume` block?)
3. Has the retro phase been executed? (Check: does Work Log have a `## Lessons` block?)

**For `feature` / `architecture-change`**: If handoff or retro is missing, AI MUST remind: "📋 Before closing: handoff and retro haven't run yet. Want me to proceed with them now?"

**For `quick-win`**: AI SHOULD ask: "Quick task done. Run a brief retro to capture lessons? (yes/skip)"

**For `tiny-fix`**: Skip entirely.

## 11. Multi-Person Collaboration Rules

### 11.1 Work Log Ownership

- **One Branch = One Owner**: Each `docs/context/work/<worklog-key>.md` Work Log MUST have exactly ONE active writer at a time.
- AI MUST write `Owner: <user-name or session-id>` in the Work Log header during `/bootstrap`.
- If a Work Log already exists with a different Owner, AI MUST warn: "⚠️ This Work Log is owned by [Owner]. Concurrent writes will cause data loss. Create a separate Work Log? (yes/no)"
- Naming convention for multi-person: `docs/context/work/<owner>-<worklog-key>.md` (e.g., `alice-feature-x.md`).
- Missing active Work Logs are recoverable during `/bootstrap`, `/plan`, and `/handoff`: resolve `<worklog-key>`, create or recover the active log, and warn the user. `/ship` may recover a follow-up log from archive context, but missing handoff references remain a hard failure.

### 11.2 Agent Identity

Every Work Log entry MUST include a compact identity line to enable cross-session debugging:

```markdown
## Session Info
@[model]:[platform]:[timestamp-or-conversation-id]
```

This enables answering: "Which AI wrote this? When? On which platform?"

### 11.3 Ship Guard (SSoT Merge Protection)

Before `/ship` writes to `current_state.md`:

1. AI MUST check if `current_state.md` has been modified since the task started (compare timestamps or last-known content hash).
2. If modified by another person/session: AI MUST warn: "⚠️ `current_state.md` was updated by another session since your task started. Please review the changes before I merge. Proceed? (yes/abort)"
3. If the user says proceed, AI MUST perform an **additive merge** (append new entries without removing existing ones), NOT a full overwrite.
