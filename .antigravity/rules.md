# Antigravity Rules

- **Ironclad Rules**: Correctness first, no evidence = no completion, stay within scope, ensure reversibility.
- **Language**: Default chat in Traditional Chinese. For English, user must prompt "Please reply in English".
- **Doc-First**: Before starting, MUST read `docs/context/current_state.md`. NO blind scanning (`ls -R`). SSoT resolves conflicts.
- **Constitution**: See `.agent/rules/engineering_guardrails.md` (Read on-demand, DO NOT load unnecessarily).
- **Security**: LEAKING SECRETS STRICTLY PROHIBITED. High-risk ops require rollback plans.
- **Command Blacklist**: `rm -rf`, `git reset --hard`, `git clean -fdx`, `docker system prune -a`, `chown -R`, `chmod -R 777`, `curl | bash`, blind `sudo`. MUST use scoped alternatives with backups.

