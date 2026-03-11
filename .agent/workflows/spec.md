---
description: Workflow for spec
---
# /spec

Convert requirements into verifiable specs and verify consistency with existing `docs/specs/`.

Output Format:

1. Goal
2. Acceptance Criteria (AC)
3. Non-goals
4. Constraints
5. API / Data Contract (Optional)
6. State Metadata: Output YAML frontmatter with `status: draft`. Transitions to `status: frozen` when user approves.
7. File Relationship: Declare if this spec EXTENDS, REPLACES, or is INDEPENDENT from any existing `docs/specs/*.md` file.

Checkpoints:

- AC MUST be objectively verifiable.
- MUST check for conflicting legacy specs.
- Non-goals MUST prevent scope creep.
- MUST NOT modify any existing spec with `status: frozen` frontmatter (Ref: §4.1 Spec Freezing).

## Output Location (Hard Rule)

- Write spec to: `docs/specs/<feature-name>.md`.
- Update `current_state.md` Spec Index with: `[<module>] docs/specs/<feature-name>.md [Draft]`.
- This file is the ONLY artifact that satisfies the Spec Gate in `/plan`.

> Note: Antigravity's `implementation_plan.md` (in brain/) is a per-conversation ephemeral artifact. It does NOT replace `docs/specs/<feature>.md` as the persistent specification SSoT.
