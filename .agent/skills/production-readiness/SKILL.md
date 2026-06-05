---
name: production-readiness
description: Pre-ship observability readiness checklist — ensures errors reach production monitoring (real log sinks / crash reporters), not just debug consoles. Auto-recommended for feature / architecture-change; applied at /review and /ship. Full body — .agents/skills/production-readiness/SKILL.md.
---

# Production Readiness (metadata summary)

Enforces observability readiness before ship: every changed `catch`/error path must log
to a **production-observable** sink (framework logger, crash reporter, structured stdout),
not a debug-only API. At `/ship`, document the error sink, health check, and rollback
signal in the Work Log.

Phase scope: `/review`, `/ship`. Read the canonical body at
`.agents/skills/production-readiness/SKILL.md` on activation.
