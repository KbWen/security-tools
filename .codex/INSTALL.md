# AI Brain Superpowers Installer (Codex)

Goal: Enable Codex (Web / App) to quickly load the workflow-first behavior of this template.

## 1) Installation (Run in target repo)

```bash
curl -fsSL <REPLACE_WITH_YOUR_TEMPLATE_RAW_DEPLOY_SCRIPT_URL> -o deploy_brain.sh
chmod +x deploy_brain.sh
./deploy_brain.sh .
```

> If you already have this repo, run directly: `./deploy_brain.sh .`

## 2) Verification

```bash
.agentcortex/bin/validate.sh
```

## 3) Codex Opening Commands (Recommended paste)

```text
Read and follow AGENTS.md first — it is the canonical governance for this repo.
Then run /bootstrap to classify your task and load context.
Use /brainstorm to clarify solutions, and /plan to generate an actionable plan.
DO NOT claim completion until /review and /test have passed.
```

