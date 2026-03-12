---
description: Workflow for review
---
# /review

Conduct strict review of current changes.

Minimum Checks:

- Logic correctness
- Compatibility risks
- Security issues (Secrets / Injections / Permissions)
- Violation of `.agent/rules/engineering_guardrails.md`
- Scope enforcement: MUST skip any file with `status: frozen` or `Finalized` metadata. Review scope is limited to current task's changed files only.

Output Format:

- Issues found (with severity)
- Fix suggestions
- Ready to commit? (Yes/No)

## Spec Compliance Check (MANDATORY for feature / architecture-change)

- Cross-reference implementation against EVERY AC in the referenced `docs/specs/<feature>.md`.
- For each AC, mark: ✅ Met / ⚠️ Partially Met (explain) / ❌ Not Met.
- If any AC is ❌: STOP. Cannot proceed to `/test` until resolved.
- `tiny-fix`, `quick-win`, and `hotfix` are EXEMPT from this check.
