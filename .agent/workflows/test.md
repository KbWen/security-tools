---
description: Workflow for test
---
# /test

Design and execute minimal necessary tests. AI drives the entire process autonomously — classify depth, generate skeletons, write tests, run adversarial cases, and persist evidence. Human review is optional, not a gate.

## Step 1: Auto-Classify Test Depth

Read the task classification from the active Work Log (`Classification:` field). If no Work Log exists (e.g., tiny-fix fast-path from bootstrap §0), infer classification from the scope of changes (number of files, modules touched, whether logic changed).

Apply the test depth matrix from `.agent/workflows/test-classify.md` to determine:
- How many tests are needed (scope)
- What evidence format to use (rigor)
- Whether adversarial testing is required (Red Team)

Do NOT ask the user which depth to use — infer it autonomously.

## Step 2: Generate Test Skeleton

Before writing any test code, generate a test blueprint per `.agent/workflows/test-skeleton.md`:
- At least 1 test per Acceptance Criterion in the spec
- At least 1 regression test per Risk identified in the plan
- Name tests descriptively so failures are self-documenting

## Step 3: Implement and Run Tests

Write test code to the project's test directory (e.g., `tests/`, `__tests__/`, or project convention). Follow naming conventions from `.agentcortex/docs/TESTING_PROTOCOL.md` if it exists; otherwise use reasonable defaults.

Run all tests. Capture pass/fail output as evidence.

## Step 4: Adversarial Test Cases (Auto-Triggered)

After standard tests pass, check if adversarial testing is required based on classification:

1. Read the auto-trigger matrix from `.agents/skills/red-team-adversarial/SKILL.md` §When to Use.
2. For `architecture-change`, also activate Beast Mode (concurrency stress, resource exhaustion, fault injection).
3. Generate adversarial test cases using the table format from the skill file.
4. Where possible, implement adversarial cases as actual test code alongside standard tests.

Skip adversarial testing entirely for `tiny-fix` and `quick-win` classifications.

## Step 5: Persist Evidence (Hard Gate)

No evidence = no completion. This is non-negotiable.

- Work Log MUST record: `Test Files: [list of test file paths]`
- Work Log MUST contain actual test output (pass/fail), not narrative claims
- If adversarial testing ran, record results under `## Red Team Findings`
- State transition: task may proceed to `/review` or `/ship` only after evidence is persisted
