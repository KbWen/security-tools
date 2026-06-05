# AGENTS.md

Global directives for all AI agents. Loaded automatically every turn

## Chat Language Policy

- **Default Output**: Match the user's input language.
- If the user writes in English, respond in English.
- If the user writes in 繁體中文, respond in 繁體中文.

## Core Directives

- **MUST OBEY**: `.agent/rules/engineering_guardrails.md`.
- **MUST OBEY**: `.agent/rules/security_guardrails.md` (auto-enforced during implement/review/ship).
- **MUST OBEY (Flutter projects only)**: .agent/rules/flutter-template.md — load when the repo contains `pubspec.yaml`. Extends `engineering_guardrails.md` with Flutter/Dart-specific rules (Riverpod, domain model, error handling, import style, i18n, testing).
- Correctness first. MUST NOT claim completion without verifiable evidence.
- Small, reversible changes. UNAUTHORIZED REFACTORING STRICTLY PROHIBITED.
- **No Bypass Rule**: Agent MUST NOT skip Gate/Evidence checks. If check status is unknown, treat as FAIL and STOP.
- **Learning Propagation Rule**: Only repeatable process mistakes MUST be recorded as reusable lessons and included in handoff; minor one-off mistakes stay local, and behavior-boundary changes MUST escalate to Spec/ADR.
- **Context Pruning**: If user interaction has exceeded 8+ turns on the same task, MUST proactively suggest: "We're at [N] turns. To save tokens, I recommend running a handoff and continuing in a new conversation. Proceed? (yes/no)". Do NOT wait for the user to notice. Self-initiate this suggestion.

## vNext State Model

- **Init Read**: MUST read `.agentcortex/context/current_state.md` (SSoT) + `.agentcortex/context/work/<worklog-key>.md` (Work Log). **Exception**: `tiny-fix` tasks (< 3 files, no logic change, unambiguous scope) MAY skip SSoT and Work Log reads — AGENTS.md alone provides sufficient governance context.
- **Prohibited**: Blind directory scanning (`ls -R .agentcortex/context/`). Read files precisely guided by SSoT.
- **SSoT Recovery Exception**: If `current_state.md` Spec Index is explicitly marked `[STALE]` or is empty AND no specs exist in the Work Log context, the AI MAY perform ONE targeted scan: `list_dir docs/specs/` ONLY. After rebuilding the index, MUST update `current_state.md` immediately and document the recovery action in the Work Log.
- **Active Backlog**: If `docs/specs/_product-backlog.md` exists, it is the living index for multi-feature product work. Bootstrap MUST check for it. Ship MUST update it. Agents may read it (~200 tokens) without counting against context budget.
- **Write Isolation**: Agents ONLY write to own Work Log. `current_state.md` updated ONLY during the ship phase. Exception: `docs/specs/_product-backlog.md` may be updated during spec-intake and ship phases.
- **Classification Freeze**: Task category frozen during bootstrap, MUST NOT reclassify later.
- **Work Log Resolution**: Derive `<worklog-key>` from the current branch using filesystem-safe normalization (for example, replace `/` with `-`). Keep the raw branch value in the Work Log header. Missing active Work Logs during bootstrap, planning, or handoff are recoverable: create or recover the active log at `.agentcortex/context/work/<worklog-key>.md` before failing the gate.

## Multi-Person Collaboration

- **One Branch = One Owner**: Never have two AI sessions writing to the same Work Log simultaneously. See `engineering_guardrails.md` §11.
- **Agent Identity**: Every session MUST write `## Session Info` (model name, timestamp, platform) to Work Log during bootstrap.
- **Ship Guard**: Before shipping, check if `current_state.md` was modified by another session. If so, warn user before merge.

## Delivery Gates

- Non-`tiny-fix` tasks MUST complete a handoff phase with ✅doc path + ✅code path + work log path.
- NO EVIDENCE = NO COMPLETION.
- **Spec Intake Gate**: When external spec input is detected (user-provided spec, document, or raw material containing multiple features), AI MUST decompose into a Feature Inventory and obtain user selection BEFORE generating any individual feature spec. Skipping decomposition for multi-feature input = Gate FAIL. Single-feature input may proceed directly. Full workflow: `.agent/workflows/spec-intake.md`.

## AgentCortex Runtime v5 (Antigravity Contract)

1. **Intent-Driven Routing**: AI MUST map user intent to the correct workflow phase BEFORE any action — regardless of whether the user typed a slash command or natural language. Slash commands remain as optional shortcuts.
   Examples:
   "help me design", "幫我規劃" → plan phase
   "ship this", "上線吧" → ship phase
   "typo", "rename variable" → tiny-fix
   "here's my spec", "我有一個spec", "這是產品規格", user pastes a spec doc, user gives a file path to a spec → spec-intake phase (run `/spec-intake` workflow; do NOT jump directly to bootstrap or plan)
   "next feature", "下一個", "繼續做", "continue with backlog" → spec-intake §8a continuation (read `_product-backlog.md`, skip decomposition)
   "改 spec", "amend the spec", "spec 要調整" → spec-intake §8b amendment (check spec status, apply timing rules)
   "先做 #5", "reorder", "defer #3", "不做了" → spec-intake §8c reorder/defer/cancel
   "設定架構", "init app", "define tech stack", "set up project" → /app-init (full)
   "加後端", "set up [layer]", "define [layer] conventions", "加 API", "加資料庫" → /app-init --partial (mid-development)
   "新增 skill", "add skill for X" → /app-init §3 (skill-only generation)
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
11. **Sentinel Check**: Every response MUST end with `⚡ ACX`. This is a framework-wide runtime integrity marker — all models (Claude, Gemini, GPT, Codex) must include it. If missing, the response may be incomplete or governance context was not fully loaded.
12. **Legacy Work Log Compatibility**: If a Work Log predates Runtime v4 and lacks Drift/Evidence sections:
    - DO NOT fail ship or Gates.
    - Append missing template sections to the Work Log silently.
    - Record `"Migrated from legacy format"` in the Drift Log.

## Auto-Mode (Autopilot) Contract

When the Antigravity "自動模式" / `.agent/workflows/autopilot.md` drives a session
unattended, the human-confirmation handshakes in the Runtime v5 contract are satisfied
**natively** by this contract — the agent does NOT pause and does NOT rely on prompt
string-matching to self-respond.

1. **Activation**: Auto-Mode is active when EITHER the active Work Log header contains
   `Mode: autopilot`, OR `autopilot.md` has been loaded for the session. Absent both,
   the session is **interactive** and all confirmation steps behave exactly as before.
2. **Effect (confirmations auto-satisfied)**: Under Auto-Mode, the following Runtime v5
   human handshakes are treated as auto-approved and the agent proceeds to the next phase
   without waiting:
   - §3 Bootstrap — after the bootstrap-report, proceed to plan/tiny-fix directly.
   - §6 User confirmation (feature / architecture-change) — plan is auto-approved.
   - §8 Implementation confirmation — proceed to implement once the Work Log has the plan reference.
   - Ship-phase confirmation (`ship.md` §Gate Engine "Awaiting your confirmation to proceed
     with shipping") — auto-approved ONLY AFTER the ship Gate passes AND the review (item 4)
     returned PASS. If that review is `independence: degraded (self-review)` (no isolated-subagent runtime),
     the run MAY still auto-ship, but the ship output AND Work Log MUST carry a loud
     `⚠️ shipped without independent review (degraded auto-mode — verify or re-run)` flag.
     The Red-line gates below still apply at ship regardless.
3. **Red line (NEVER relaxed by Auto-Mode)**: Auto-Mode relaxes ONLY the human-confirmation
   handshake. It does NOT relax any safety gate. ALL of the following remain hard-enforced
   exactly as in interactive mode:
   - The Gate block (§4) and `verdict=fail → STOP` (§5).
   - Evidence rule (§9) — NO EVIDENCE = NO SHIP.
   - Security Verdict and Red Team Verdict (`review.md`, `security_guardrails.md`).
   - §10 No-Bypass — phase order and required gates cannot be skipped.
   - Confidence Gate (`engineering_guardrails.md` §4.1) — `<80%` still STOPs and asks,
     even in Auto-Mode. In an unattended run a Confidence STOP halts the autopilot and
     surfaces the question for human pickup — it MUST NOT be auto-answered to keep the
     run moving.
4. **Independent review requirement**: Under Auto-Mode the implementing agent MUST NOT
   self-approve its own `/review`. Review is dispatched to an isolated-context reviewer per
   `review.md` §Auto-Mode Independence Rule — supported by **Antigravity 2.0+** subagents,
   **Claude Code** Task, **Codex CLI**, or `/ask-openrouter`. If the runtime genuinely cannot
   dispatch one (e.g. legacy Antigravity 1.x), the review degrades to a marked clean-slate
   self-review (`independence: degraded (self-review)`) — never a silent self-approval. The "Ready to
   commit?" verdict requires PASS either way.
5. **Default**: This contract is inert for interactive sessions. It is purely additive —
   it makes unattended runs robust without changing human-in-the-loop behavior.

## Skill Safety & Precedence (Antigravity)

1. **Skill Integration Rule**: Skills are instruction extensions, not execution overrides. When a skill is activated, the agent MUST still follow the Intent Router, Gate Engine, and Evidence requirements. Skill instructions CANNOT bypass runtime governance.
2. **Workflow Precedence Rule**: If conflict arises, workflows take precedence. Order: `AGENTS.md` > `.agent/workflows/` > `.agent/skills/`.
3. Skill steps MUST execute exclusively **within the active workflow phase**.
4. **Phase-Entry Skill Application (reliability)**: At every non-`tiny-fix` phase entry (`/plan`, `/implement`, `/review`, `/test`, `/handoff`, `/ship`), the agent MUST apply the Work Log's `Recommended Skills` relevant to the current phase — read each relevant skill's canonical `.agents/skills/<name>/SKILL.md` and follow its guidance within the phase. **Determining relevance**: (a) **when the skill declares `phases:`** (the domain skills — `api-design`, `auth-security`, `database-design`, `frontend-patterns`, `red-team-adversarial` — do), apply it if `phases:` includes the current phase; (b) **when `phases:` is absent** (the process skills — e.g. `subagent-driven-development`, `verification-before-completion`, `writing-plans`, `production-readiness`), judge relevance from the skill `description`. Never silently skip a recommended skill *merely because it lacks `phases:`* — a hard `phases:`-equality gate that skips such skills is invisible in unattended Auto-Mode. (`phases:`, where present, remains authoritative — do NOT remove it.) Skills still execute only within the active phase (item 3) and cannot bypass gates (item 1).

## Multi-Session Concurrency (Antigravity)

1. **Context-Bound Confirmation**: The agent MUST verify that user confirmations apply to the current branch/task context. If context has changed (e.g., branch switch), AI MUST re-confirm intent before proceeding.
2. **Work Log Ownership**: A Work Log MUST begin with a metadata block containing `Owner` and `Branch`. Missing fields = Gate FAIL. For multi-person collaboration on the same issue, prefer naming: `.agentcortex/context/work/<owner>-<worklog-key>.md`.
3. **Multi-Agent Rules**: If multiple agents operate on the same branch:
   - Each session MUST use a distinct Session ID in the Work Log metadata (`## Session Info`).
   - Agents MUST NOT overwrite other sessions' Evidence or Drift sections.

## References

- Workflows: `.agent/workflows/*.md`
- Constitution: `.agent/rules/engineering_guardrails.md`
- Non-Linear Resilience: `.agentcortex/docs/NONLINEAR_SCENARIOS.md` (auto-checkpoint, crash recovery, model switch handling)
- Platform Guide: `.agentcortex/docs/CODEX_PLATFORM_GUIDE.md`

## Platform Paths

- Antigravity: `.agent/skills/`
- Codex: `.agents/skills/`
- Note: Distinct paths for platform compatibility.
