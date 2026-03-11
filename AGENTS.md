# AGENTS.md

Global directives for all AI agents. Loaded automatically every turn

## Chat Language Policy

- **Default Output**: Match the user's input language.
- If the user writes in English, respond in English.
- If the user writes in 繁體中文, respond in 繁體中文.

## Core Directives

- **MUST OBEY**: `.agent/rules/engineering_guardrails.md`.
- Correctness first. MUST NOT claim completion without verifiable evidence.
- Small, reversible changes. UNAUTHORIZED REFACTORING STRICTLY PROHIBITED.
- **No Bypass Rule**: Agent MUST NOT skip Gate/Evidence checks. If check status is unknown, treat as FAIL and STOP.
- **Learning Propagation Rule**: Only repeatable process mistakes MUST be recorded as reusable lessons and included in handoff; minor one-off mistakes stay local, and behavior-boundary changes MUST escalate to Spec/ADR.
- **Context Pruning**: If user interaction has exceeded 8+ turns on the same task, MUST proactively suggest: "We're at [N] turns. To save tokens, I recommend running a handoff and continuing in a new conversation. Proceed? (yes/no)". Do NOT wait for the user to notice. Self-initiate this suggestion.

## vNext State Model

- **Init Read**: MUST read `docs/context/current_state.md` (SSoT) + `docs/context/work/<worklog-key>.md` (Work Log).
- **Prohibited**: Blind directory scanning (`ls -R docs/`). Read files precisely guided by SSoT.
- **SSoT Recovery Exception**: If `current_state.md` Spec Index is explicitly marked `[STALE]` or is empty AND no specs exist in the Work Log context, the AI MAY perform ONE targeted scan: `list_dir docs/specs/` ONLY. After rebuilding the index, MUST update `current_state.md` immediately and document the recovery action in the Work Log.
- **Write Isolation**: Agents ONLY write to own Work Log. `current_state.md` updated ONLY during the ship phase.
- **Classification Freeze**: Task category frozen during bootstrap, MUST NOT reclassify later.
- **Work Log Resolution**: Derive `<worklog-key>` from the current branch using filesystem-safe normalization (for example, replace `/` with `-`). Keep the raw branch value in the Work Log header. Missing active Work Logs during bootstrap, planning, or handoff are recoverable: create or recover the active log before failing the gate.

## Multi-Person Collaboration

- **One Branch = One Owner**: Never have two AI sessions writing to the same Work Log simultaneously. See `engineering_guardrails.md` §11.
- **Agent Identity**: Every session MUST write `## Session Info` (model name, timestamp, platform) to Work Log during bootstrap.
- **Ship Guard**: Before shipping, check if `current_state.md` was modified by another session. If so, warn user before merge.

## Delivery Gates

- Non-`tiny-fix` tasks MUST complete a handoff phase with ✅doc path + ✅code path + work log path.
- NO EVIDENCE = NO COMPLETION.

## AgentCortex Runtime v5 (Antigravity Contract)

1. **Intent-Driven Routing**: AI MUST map user intent to the correct workflow phase BEFORE any action — regardless of whether the user typed a slash command or natural language. Slash commands remain as optional shortcuts.
   Examples:
   "help me design", "幫我規劃" → plan phase
   "ship this", "上線吧" → ship phase
   "typo", "rename variable" → tiny-fix
2. **tiny-fix fast path**:
   <5 lines change, no logic change → execute directly.
   If logic change or multi-file → escalate to hotfix.
3. **Bootstrap phase**:
   When starting a new task, AI MUST execute the bootstrap phase (load context, classify task) and output a bootstrap-report ONLY, then STOP.
   Next step must be planning or tiny-fix. NO code allowed in bootstrap.
4. **Gate requirement** (non tiny-fix):
   Before entering plan or ship phase, output this block FIRST:
   gate: plan|ship
   classification: tiny-fix|quick-win|hotfix|feature|architecture-change
   verdict: pass|fail
   missing: []
5. If verdict=fail → print gate + missing items ONLY and STOP.
6. **User confirmation** (feature / architecture-change only):
   After gate passes, AI presents the plan summary and waits for user confirmation.
   Any affirmative response (e.g., "OK", "go ahead", "好", "proceed") triggers the next phase. No specific keyword required.
7. After user confirms planning:
   Output PLAN ONLY (no code).
   Plan MUST include:
   Docs:
   - docs/specs/&lt;feature&gt;.md
8. **Implementation confirmation**:
   After plan is presented, AI waits for user confirmation before implementing.
   Requirement: Work Log must contain plan reference.
9. **Evidence rule**:
   NO EVIDENCE = NO SHIP.
10. User requests cannot bypass Gate rules. The AI MUST strictly follow phase order (e.g., Bootstrap -> Plan -> Ship). EVEN IF the human explicitly asks to skip a step, the AI MUST refuse to skip those required workflow gates.
11. **Sentinel Check**: Every response MUST end with `⚡ ACX`. If this token is missing, it signifies the prompt was truncated or not fully loaded.
12. **Legacy Work Log Compatibility**: If a Work Log predates Runtime v4 and lacks Drift/Evidence sections:
    - DO NOT fail ship or Gates.
    - Append missing template sections to the Work Log silently.
    - Record `"Migrated from legacy format"` in the Drift Log.

## Skill Safety & Precedence (Antigravity)

1. **Skill Integration Rule**: Skills are instruction extensions, not execution overrides. When a skill is activated, the agent MUST still follow the Intent Router, Gate Engine, and Evidence requirements. Skill instructions CANNOT bypass runtime governance.
2. **Workflow Precedence Rule**: If conflict arises, workflows take precedence. Order: `AGENTS.md` > `.agent/workflows/` > `.agent/skills/`.
3. Skill steps MUST execute exclusively **within the active workflow phase**.

## Multi-Session Concurrency (Antigravity)

1. **Context-Bound Confirmation**: The agent MUST verify that user confirmations apply to the current branch/task context. If context has changed (e.g., branch switch), AI MUST re-confirm intent before proceeding.
2. **Work Log Ownership**: A Work Log MUST begin with a metadata block containing `Owner` and `Branch`. Missing fields = Gate FAIL. For multi-person collaboration on the same issue, prefer naming: `docs/context/work/<owner>-<worklog-key>.md`.
3. **Multi-Agent Rules**: If multiple agents operate on the same branch:
   - Each session MUST use a distinct Session ID in the Work Log metadata (`## Session Info`).
   - Agents MUST NOT overwrite other sessions' Evidence or Drift sections.

## References

- Workflows: `.agent/workflows/*.md`
- Constitution: `.agent/rules/engineering_guardrails.md`
- Non-Linear Resilience: `agentcortex/docs/NONLINEAR_SCENARIOS.md` (auto-checkpoint, crash recovery, model switch handling)
- Platform Guide: `agentcortex/docs/CODEX_PLATFORM_GUIDE.md`

## Platform Paths

- Antigravity: `.agent/skills/`
- Codex: `.agents/skills/`
- Note: Distinct paths for platform compatibility.
