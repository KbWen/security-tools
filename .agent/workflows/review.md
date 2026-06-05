---
description: Strict pre-commit review of the current changes — logic correctness, scope/regression, OWASP security scan, classification-based Red Team, spec-AC compliance, and error observability. Triggers on "review", "幫我看", "check before commit", "上線前檢查", or entry to the review phase. Under Auto-Mode it MUST run as an independent fresh-context reviewer.
---
# /review

Conduct strict review of current changes.

## Auto-Mode Independence Rule (MANDATORY under Auto-Mode)

When Auto-Mode is active (`Mode: autopilot` in the Work Log header OR `autopilot.md` loaded; see `AGENTS.md` §Auto-Mode
(Autopilot) Contract), the implementing agent MUST NOT review and self-approve its own
work — that is a player-and-referee gate hole, and in unattended runs it is the ONLY gate
between generated code and a commit.

1. **Dispatch to an independent reviewer in a FRESH context** (a subagent), not the agent
   that wrote the code. Apply `subagent-driven-development` and `dispatching-parallel-agents`.
2. The reviewer receives ONLY the diff + spec ACs + this workflow — no implementation
   rationale — so it judges the code, not the author's intent.
3. Full Red Team is mandatory for `feature` / `architecture-change` (per the matrix below).
4. The **"Ready to commit?"** verdict passes ONLY on the independent reviewer's explicit
   PASS. The implementing agent records the verdict but does not author it.

For interactive (non-Auto-Mode) sessions this rule is advisory — the human reviewer is the
independent check.

## Skill-Aware Review (Pre-Check)

IF the active Work Log contains a `Recommended Skills` entry with skills relevant to review (per `AGENTS.md` §Skill Safety item 4 — a skill's `phases:` includes `review` when that field is present, otherwise relevance is judged from the skill `description`):
1. READ those `.agents/skills/<name>/SKILL.md` files now (if not already loaded during /implement).
2. Apply each skill's guidance as additional, domain-specific review criteria.
3. Explicitly state: "Reviewing with [skill-name] applied."

This ensures domain-specific review criteria (API conventions, frontend patterns, DB safety, auth compliance) are enforced — not just generic code review.

## Minimum Checks

- Logic correctness
- Compatibility risks
- Violation of `.agent/rules/engineering_guardrails.md`
- Scope enforcement: MUST skip any file with `status: frozen` or `Finalized` metadata. Review scope is limited to current task's changed files only.

## Security Scan (MANDATORY — Auto-Enforced)

Execute `.agent/rules/security_guardrails.md` §1–§4 against all changed files:

1. **Always-On Checks** (every review): Broken Access Control (A01), Cryptographic Failures (A02), Injection (A03), Secret Detection (§3).
2. **Context Checks** (when relevant code touched): A04–A10 per trigger rules in security_guardrails.md §2.
3. **Dependency Check** (§4): If any dependency manifest changed, flag new dependencies.

### Security Verdict

- Any **CRITICAL/HIGH** finding → Review verdict = **Not Ready**. MUST fix before proceeding.
- **MEDIUM** findings → Flag in review output. Proceed allowed with user acknowledgment.
- **LOW** findings → Informational only.
- Output findings using format defined in security_guardrails.md §5.

## Red Team Scan (Auto-Triggered — Classification-Based)

After completing the Security Scan above, AI MUST check the task classification from the active Work Log and apply the Red Team skill if applicable.

**Auto-Trigger Logic**:
1. Read `Classification:` from `.agentcortex/context/work/<worklog-key>.md`.
2. Apply the auto-trigger matrix defined in `.agents/skills/red-team-adversarial/SKILL.md` §When to Use.
3. Execute the corresponding mode from that skill file.

### Red Team Verdict (separate from Security Verdict)

- **CRITICAL** Red Team finding → Review verdict = **Not Ready**. MUST fix before proceeding.
- **HIGH** Red Team finding → Does NOT block. MUST record risk decision in Work Log `## Red Team Findings` section. Recommend using `/decide` to document accept/defer rationale.
- **MEDIUM / LOW** Red Team finding → Advisory only.

Output findings using the Red Team Report format defined in the skill file.

## Error Observability Compliance (feature / architecture-change)

For `feature` / `architecture-change`, apply the `production-readiness` skill's Error
Surface Audit to every changed `catch` / error-handling block:

- Logging call exists (not an empty `catch {}` — also enforced by `engineering_guardrails.md` §5.2).
- The log sink is **production-observable** (framework logger / crash reporter / structured
  stdout), not a debug-only API.
- Error context is actionable (operation + identifiers + error type), not `"error occurred"`.

A debug-only or missing error sink on a changed error path → flag as a review finding.
Full checklist: `.agents/skills/production-readiness/SKILL.md`.

## Self-Check Protocol (Auto — Before Presenting Results)

AI MUST verify its own review before outputting:

1. **Scope check**: List every file changed. Any file NOT in the original plan? Flag it.
2. **Regression check**: For each changed function/export, state: "Callers: [list]. Breaking change: yes/no."
3. **Evidence check**: Every claim MUST have a `file:line` reference. No narrative-only assertions.

## Output Format

- Issues found (with severity)
- Security findings (per §5 format above)
- Red Team findings (if triggered — per Red Team Report format)
- Fix suggestions
- Ready to commit? (Yes/No — blocked if unresolved CRITICAL/HIGH security findings OR CRITICAL Red Team findings)

## Spec Compliance Check (MANDATORY for feature / architecture-change)

- Cross-reference implementation against EVERY AC in the referenced `docs/specs/<feature>.md`.
- For each AC, mark: ✅ Met / ⚠️ Partially Met (explain) / ❌ Not Met.
- If any AC is ❌: STOP. Cannot proceed to `/test` until resolved.
- `tiny-fix`, `quick-win`, and `hotfix` are EXEMPT from this check.
