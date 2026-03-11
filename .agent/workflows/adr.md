---
description: Workflow for adr - Architecture Decision Record Workflow
---
# /adr - Architecture Decision Record Workflow

Guides AI to create standardized architectural decision records.

## Execution Steps

1. **Search History**: `ls docs/adr/` to check existing decisions and avoid conflicts.
2. **Allocate ID**: Find the next available ID (e.g., ADR-005).
3. **Generate Content**: Create `docs/adr/ADR-[ID]-[name].md` strictly following this format:
    - **Status**: Proposed / Accepted / Deprecated
    - **Context**: What is the problem? Background?
    - **Decision**: What exactly are we doing?
    - **Consequences**: Pros and cons of this decision.
4. **Relational Linking**: Cite this ADR in affected code or Specs.


