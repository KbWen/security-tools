---
name: hotfix
description: Emergency patch workflow. Root cause analysis followed by minimal fix.
tasks:
  - research
  - plan
  - implement
  - review
  - test
---

# Hotfix Workflow

1. `/research`: Define root cause and blast radius.
2. Skill `systematic-debugging`: Converge via "Observe -> Hypothesize -> Verify -> Fix".
3. `/plan`: Define minimal change, risks, and rollback.
4. `/implement`: Execute minimal patch.
5. `/review`: Document alternatives and trade-offs.
6. `/test`: Reproduce issue + run regression cases.

