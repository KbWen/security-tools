---
description: Workflow for retro
---
# /retro

Conduct a retrospective for the current task.

Output Format:

1. Keep (What went well)
2. Problem (What to improve)
3. Try (Action items for next time)
4. Doc Health: Did this task create or reference more than 1 spec file for the same feature?
   - If YES: Append `[MERGE-PROPOSED: <other-spec-file>]` to the relevant entry in `current_state.md` Spec Index.
5. Lessons Append: If Problems exist, append to the current Work Log (max 3 bullets).
   - **Global Candidate?**: If a lesson is a recurring pattern with a system-wide fix, tag it as `[GLOBAL-CANDIDATE]` for promotion during `/ship`.
6. Spec Seeds: Did the AI make any architectural decisions or discover new feature requirements during development that are NOT currently written in any formal Spec?
   - If YES: Append these to the current Work Log under a `## Spec Seeds` heading, and proactively ask the user: "I recorded [N] undocumented design decisions. Would you like me to formally add them to the Specs now?"
7. Spec Gap Check: Did this task modify code in a module/feature area that has NO Spec coverage at all in the Spec Index?
   - If YES and the change was `quick-win` or higher: Append to `## Spec Seeds` with tag `[NEW-SPEC-NEEDED]` and notify: "⚠️ Module [name] has no Spec coverage. Recommend creating `.agentcortex/specs/<module-name>.md` to prevent future documentation decay."
   - Advisory for `quick-win`; MANDATORY action for `feature` and above.

```markdown
## Lessons
- [Pattern]: [What went wrong + why]
- [Pattern]: ...

## Spec Seeds
- [Decision/Requirement]: [Context]
```
