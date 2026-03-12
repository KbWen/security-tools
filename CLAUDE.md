# Claude Integration Entry

This repository can be used with Claude via a documentation-first adapter layer.

## Goal

Keep one canonical governance system (`AGENTS.md`, `.agent/`, `docs/context/`) and add a minimal Claude-compatible entry without duplicating core rules.

## Startup Prompt (for Claude users)

```text
Read and follow AGENTS.md first.
Then run /bootstrap behavior using:
- docs/context/current_state.md
- docs/context/work/<branch>.md
Use the same gates and evidence rules as defined in AGENTS.md and .agent/rules/engineering_guardrails.md.
```

## Command Templates

Use templates in `.claude/commands/`:

- `bootstrap.md`
- `plan.md`
- `implement.md`
- `review.md`
- `test.md`
- `handoff.md`
- `ship.md`

## Notes

- No Claude API or CLI is required for this baseline integration.
- Validate structure with `./tools/validate.sh`.
