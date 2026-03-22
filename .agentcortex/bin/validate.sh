#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLATFORM_DOC="$ROOT/.agentcortex/docs/CODEX_PLATFORM_GUIDE.md"
CLAUDE_PLATFORM_DOC="$ROOT/.agentcortex/docs/CLAUDE_PLATFORM_GUIDE.md"
EXAMPLES_DOC="$ROOT/.agentcortex/docs/PROJECT_EXAMPLES.md"
PROJECT_AGENTS_FILE="$ROOT/AGENTS.md"
PROJECT_CLAUDE_FILE="$ROOT/CLAUDE.md"
WORKFLOWS_DIR="$ROOT/.agent/workflows"
CLAUDE_COMMANDS_DIR="$ROOT/.claude/commands"
CODEX_INSTALL="$ROOT/.codex/INSTALL.md"
CODEX_RULES="$ROOT/.codex/rules/default.rules"
ROOT_DEPLOY_SH="$ROOT/deploy_brain.sh"
ROOT_DEPLOY_PS1="$ROOT/deploy_brain.ps1"
ROOT_DEPLOY_CMD="$ROOT/deploy_brain.cmd"
CANONICAL_DEPLOY_SH="$ROOT/.agentcortex/bin/deploy.sh"
CANONICAL_DEPLOY_PS1="$ROOT/.agentcortex/bin/deploy.ps1"
CANONICAL_VALIDATE_SH="$ROOT/.agentcortex/bin/validate.sh"
CANONICAL_VALIDATE_PS1="$ROOT/.agentcortex/bin/validate.ps1"
CANONICAL_AUDIT_SH="$ROOT/.agentcortex/tools/audit_ai_paths.sh"
TEXT_INTEGRITY_CHECK_PY="$ROOT/.agentcortex/tools/check_text_integrity.py"
TEXT_INTEGRITY_BASELINE="$ROOT/.agentcortex/tools/text_integrity_baseline.txt"

required_files=(
  "$WORKFLOWS_DIR/hotfix.md"
  "$WORKFLOWS_DIR/worktree-first.md"
  "$WORKFLOWS_DIR/new-feature.md"
  "$WORKFLOWS_DIR/medium-feature.md"
  "$WORKFLOWS_DIR/small-fix.md"
  "$WORKFLOWS_DIR/govern-docs.md"
  "$WORKFLOWS_DIR/handoff.md"
  "$WORKFLOWS_DIR/bootstrap.md"
  "$WORKFLOWS_DIR/plan.md"
  "$WORKFLOWS_DIR/implement.md"
  "$WORKFLOWS_DIR/review.md"
  "$WORKFLOWS_DIR/help.md"
  "$WORKFLOWS_DIR/test-skeleton.md"
  "$WORKFLOWS_DIR/commands.md"
  "$WORKFLOWS_DIR/test.md"
  "$WORKFLOWS_DIR/ship.md"
  "$WORKFLOWS_DIR/decide.md"
  "$WORKFLOWS_DIR/test-classify.md"
  "$WORKFLOWS_DIR/spec-intake.md"
)

claude_required_files=(
  "$CLAUDE_COMMANDS_DIR/spec-intake.md"
  "$CLAUDE_COMMANDS_DIR/bootstrap.md"
  "$CLAUDE_COMMANDS_DIR/plan.md"
  "$CLAUDE_COMMANDS_DIR/implement.md"
  "$CLAUDE_COMMANDS_DIR/review.md"
  "$CLAUDE_COMMANDS_DIR/test.md"
  "$CLAUDE_COMMANDS_DIR/handoff.md"
  "$CLAUDE_COMMANDS_DIR/ship.md"
  "$CLAUDE_COMMANDS_DIR/decide.md"
  "$CLAUDE_COMMANDS_DIR/test-classify.md"
)

for f in "${required_files[@]}"; do
  [[ -f "$f" ]] || { echo "missing required file: $f"; exit 1; }
done
for f in "${claude_required_files[@]}"; do
  [[ -f "$f" ]] || { echo "missing claude adapter file: $f"; exit 1; }
done
for f in \
  "$PLATFORM_DOC" \
  "$CLAUDE_PLATFORM_DOC" \
  "$EXAMPLES_DOC" \
  "$PROJECT_AGENTS_FILE" \
  "$PROJECT_CLAUDE_FILE" \
  "$ROOT_DEPLOY_SH" \
  "$ROOT_DEPLOY_PS1" \
  "$ROOT_DEPLOY_CMD" \
  "$CANONICAL_DEPLOY_SH" \
  "$CANONICAL_DEPLOY_PS1" \
  "$CANONICAL_VALIDATE_SH" \
  "$CANONICAL_VALIDATE_PS1" \
  "$CANONICAL_AUDIT_SH" \
  "$TEXT_INTEGRITY_CHECK_PY" \
  "$TEXT_INTEGRITY_BASELINE"; do
  [[ -f "$f" ]] || { echo "missing required file: $f"; exit 1; }
done

[[ -d "$WORKFLOWS_DIR" ]] || { echo "missing workflows dir: $WORKFLOWS_DIR"; exit 1; }
[[ -d "$CLAUDE_COMMANDS_DIR" ]] || { echo "missing claude commands dir: $CLAUDE_COMMANDS_DIR"; exit 1; }
[[ -d "$ROOT/.agents/skills" ]] || { echo "missing codex skills dir: $ROOT/.agents/skills"; exit 1; }
[[ -d "$ROOT/.agent/skills" ]] || { echo "missing agent skills canonical dir: $ROOT/.agent/skills"; exit 1; }

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  PYTHON_BIN=
fi
if [[ -n "$PYTHON_BIN" ]]; then
  "$PYTHON_BIN" "$TEXT_INTEGRITY_CHECK_PY" --root "$ROOT" --baseline "$TEXT_INTEGRITY_BASELINE"
else
  echo "warning: skipping text integrity check because python3/python is unavailable" >&2
fi
[[ ! -f "$ROOT/tools/audit_ai_paths.sh" ]] || { echo "legacy audit helper should move under .agentcortex/tools/: $ROOT/tools/audit_ai_paths.sh"; exit 1; }

for skill_file in "$ROOT"/.agent/skills/*; do
  [[ -f "$skill_file" ]] || continue
  skill_name="$(basename "$skill_file")"
  [[ "$skill_name" == ".gitkeep" ]] && continue
  codex_skill_path="$ROOT/.agents/skills/$skill_name"
  [[ -s "$skill_file" ]] || { echo "empty skill metadata: $skill_file"; exit 1; }
  [[ -d "$codex_skill_path" ]] || { echo "missing codex skill dir: $codex_skill_path"; exit 1; }
  [[ -f "$codex_skill_path/SKILL.md" ]] || { echo "missing skill definition: $codex_skill_path/SKILL.md"; exit 1; }
done

[[ -f "$ROOT/.antigravity/rules.md" ]] || { echo "missing antigravity rules: $ROOT/.antigravity/rules.md"; exit 1; }
[[ -f "$ROOT/.agent/rules/rules.md" ]] || { echo "missing legacy rules copy: $ROOT/.agent/rules/rules.md"; exit 1; }
[[ -f "$CODEX_INSTALL" ]] || { echo "missing codex install doc: $CODEX_INSTALL"; exit 1; }

grep -q '\.antigravity/rules\.md' "$ROOT/.agent/rules/rules.md" || {
  echo "legacy rules missing canonical redirect: $ROOT/.agent/rules/rules.md"
  exit 1
}
grep -q 'legacy compatibility' "$ROOT/.agent/rules/rules.md" || {
  echo "legacy rules missing compatibility marker: $ROOT/.agent/rules/rules.md"
  exit 1
}

grep -q 'docker system prune -a' "$ROOT/.antigravity/rules.md" || { echo "rules missing dangerous command: docker system prune -a in $ROOT/.antigravity/rules.md"; exit 1; }
grep -q 'chown -R' "$ROOT/.antigravity/rules.md" || { echo "rules missing dangerous command: chown -R in $ROOT/.antigravity/rules.md"; exit 1; }
grep -q 'rollback' "$ROOT/.antigravity/rules.md" || { echo "rules missing rollback reminder in $ROOT/.antigravity/rules.md"; exit 1; }

ACTIVE_CODEX_RULES="$ROOT/codex/rules/default.rules"
[[ -f "$ACTIVE_CODEX_RULES" ]] || ACTIVE_CODEX_RULES="$CODEX_RULES"
if [[ -f "$ACTIVE_CODEX_RULES" ]]; then
  grep -q '^prefix_rule("' "$ACTIVE_CODEX_RULES" || { echo "codex rules missing prefix_rule(): $ACTIVE_CODEX_RULES"; exit 1; }
  grep -q 'docker system prune -a' "$ACTIVE_CODEX_RULES" || { echo "codex rules missing dangerous command: docker system prune -a"; exit 1; }
  grep -q 'chown -R' "$ACTIVE_CODEX_RULES" || { echo "codex rules missing dangerous command: chown -R"; exit 1; }
fi

grep -F -q -- '.agentcortex/bin/deploy.sh' "$ROOT_DEPLOY_SH" || { echo "deploy wrapper missing canonical reference: $ROOT_DEPLOY_SH"; exit 1; }
grep -F -q -- "'.agentcortex', 'bin', 'deploy.ps1'" "$ROOT_DEPLOY_PS1" || { echo "deploy wrapper missing canonical reference: $ROOT_DEPLOY_PS1"; exit 1; }
grep -F -q -- '.agentcortex\bin\deploy' "$ROOT_DEPLOY_CMD" || { echo "deploy wrapper missing canonical reference: $ROOT_DEPLOY_CMD"; exit 1; }
worklog_contract_files=(
  "$ROOT/AGENTS.md"
  "$ROOT/.agent/rules/engineering_guardrails.md"
  "$ROOT/.agent/rules/security_guardrails.md"
  "$ROOT/.agent/rules/state_machine.md"
  "$ROOT/.agent/workflows/bootstrap.md"
  "$ROOT/.agent/workflows/plan.md"
  "$ROOT/.agent/workflows/handoff.md"
  "$ROOT/.agent/workflows/ship.md"
  "$PLATFORM_DOC"
  "$ROOT/.agentcortex/docs/NONLINEAR_SCENARIOS.md"
  "$ROOT/.agentcortex/docs/guides/antigravity-v5-runtime.md"
)
for f in "${worklog_contract_files[@]}"; do
  grep -F -q -- '<worklog-key>' "$f" || { echo "worklog contract missing normalized key reference: $f"; exit 1; }
  if grep -F -q -- 'docs/context/work/<branch-name>.md' "$f"; then
    echo "stale branch-name worklog path contract: $f"
    exit 1
  fi
  if grep -F -q -- 'docs/context/work/<branch>.md' "$f"; then
    echo "stale raw branch worklog path contract: $f"
    exit 1
  fi
done

archive_contract_files=(
  "$ROOT/.agent/workflows/handoff.md"
  "$ROOT/.agentcortex/docs/guides/token-governance.md"
  "$ROOT/.agentcortex/docs/guides/portable-minimal-kit.md"
)
for f in "${archive_contract_files[@]}"; do
  grep -F -q -- '<worklog-key>-<YYYYMMDD>' "$f" || { echo "archive worklog contract missing normalized key reference: $f"; exit 1; }
  if grep -F -q -- 'docs/context/archive/work/<branch>-<YYYYMMDD>.md' "$f"; then
    echo "stale archive branch worklog path contract: $f"
    exit 1
  fi
done

grep -F -q -- 'LEGACY_IGNORE_START="# AI Brain OS - Agent System & Local Context"' "$CANONICAL_DEPLOY_SH" || {
  echo "deploy script missing legacy ignore marker support"
  exit 1
}
grep -F -q -- 'strip_managed_ignore_blocks() {' "$CANONICAL_DEPLOY_SH" || {
  echo "deploy script missing managed ignore replacement helper"
  exit 1
}
grep -F -q -- '.agentcortex/bin/' "$CANONICAL_DEPLOY_SH" || {
  echo "deploy script missing canonical namespace deployment path"
  exit 1
}

DEPLOY_IGNORE_BLOCK="$(awk '
/^# AgentCortex Template - Downstream Ignore Defaults$/ { capture = 1 }
capture { print }
/^# End AgentCortex Template - Downstream Ignore Defaults$/ {
  if (capture) {
    exit
  }
}
' "$CANONICAL_DEPLOY_SH")"

[[ -n "$DEPLOY_IGNORE_BLOCK" ]] || {
  echo "deploy ignore block missing from deploy script"
  exit 1
}

for pattern in \
  '# AgentCortex Template - Downstream Ignore Defaults' \
  '.agentcortex/context/work/*.md' \
  '.agentcortex/context/private/' \
  '.agent/private/' \
  '.agentcortex-src/' \
  '*.acx-incoming' \
  '.openrouter/' \
  '.claude-chat/' \
  '.cursor/' \
  '.antigravity/scratch/' \
  '# End AgentCortex Template - Downstream Ignore Defaults'; do
  printf '%s\n' "$DEPLOY_IGNORE_BLOCK" | grep -x -F -q -- "$pattern" || {
    echo "deploy ignore block missing required pattern: $pattern"
    exit 1
  }
done
# Check negation pattern separately (grep -x -F doesn't handle leading '!')
printf '%s\n' "$DEPLOY_IGNORE_BLOCK" | grep -F -q '.agentcortex/context/work/.gitkeep' || {
  echo "deploy ignore block missing .gitkeep negation pattern"
  exit 1
}

# Ensure SSoT and archive are NOT gitignored downstream (must persist for continuity)
for forbidden_downstream_pattern in \
  '.agentcortex/context/current_state.md' \
  '.agentcortex/context/archive/'; do
  if printf '%s\n' "$DEPLOY_IGNORE_BLOCK" | grep -x -F -q -- "$forbidden_downstream_pattern"; then
    echo "deploy ignore block must NOT ignore persistent SSoT artifact: $forbidden_downstream_pattern"
    exit 1
  fi
done

# Ensure deploy wrappers and manifest are NOT in the ignore block (must stay tracked)
for must_track_pattern in \
  'deploy_brain.sh' \
  'deploy_brain.ps1' \
  'deploy_brain.cmd' \
  '.agentcortex-manifest'; do
  if printf '%s\n' "$DEPLOY_IGNORE_BLOCK" | grep -x -F -q -- "$must_track_pattern"; then
    echo "deploy ignore block must not include tracked file: $must_track_pattern"
    exit 1
  fi
done

for localized_file in \
  "$ROOT/README_zh-TW.md" \
  "$ROOT/.agentcortex/docs/TESTING_PROTOCOL_zh-TW.md" \
  "$ROOT/.agentcortex/docs/guides/audit-guardrails_zh-TW.md"; do
  [[ -f "$localized_file" ]] || { echo "missing localized file: $localized_file"; exit 1; }
done

grep -F -q -- '從「流程驅動」進化到「自我管理」的專業級 AI Agent 核心架構。' "$ROOT/README_zh-TW.md" || {
  echo "localized doc appears mojibaked or re-encoded: $ROOT/README_zh-TW.md"
  exit 1
}
grep -F -q -- '測試教戰守則' "$ROOT/.agentcortex/docs/TESTING_PROTOCOL_zh-TW.md" || {
  echo "localized doc appears mojibaked or re-encoded: $ROOT/.agentcortex/docs/TESTING_PROTOCOL_zh-TW.md"
  exit 1
}
grep -F -q -- 'Why AgentCortex?' "$ROOT/README.md" || {
  echo "english doc appears mojibaked or re-encoded: $ROOT/README.md"
  exit 1
}
grep -F -q -- 'Test 1: Invisible Assistant Check (.gitignore Automation)' "$ROOT/.agentcortex/docs/guides/audit-guardrails.md" || {
  echo "english doc appears mojibaked or re-encoded: $ROOT/.agentcortex/docs/guides/audit-guardrails.md"
  exit 1
}
grep -F -q -- '為什麼不寫成自動化 Shell Script？' "$ROOT/.agentcortex/docs/guides/audit-guardrails_zh-TW.md" || {
  echo "localized doc appears mojibaked or re-encoded: $ROOT/.agentcortex/docs/guides/audit-guardrails_zh-TW.md"
  exit 1
}

WORKLOG_MAX_LINES="${WORKLOG_MAX_LINES:-300}"
WORKLOG_MAX_KB="${WORKLOG_MAX_KB:-12}"
WORKLOG_DIR="$ROOT/.agentcortex/context/work"
if [[ -d "$WORKLOG_DIR" ]]; then
  worklog_warnings=0
  for wl in "$WORKLOG_DIR"/*.md; do
    [[ -f "$wl" ]] || continue
    wl_lines="$(wc -l < "$wl")"
    wl_kb="$(( $(wc -c < "$wl") / 1024 ))"
    if [[ "$wl_lines" -gt "$WORKLOG_MAX_LINES" ]] || [[ "$wl_kb" -gt "$WORKLOG_MAX_KB" ]]; then
      echo "warning: work log needs compaction: $(basename "$wl") (${wl_lines} lines, ${wl_kb}KB)" >&2
      worklog_warnings=$((worklog_warnings + 1))
    fi
  done
  if [[ "$worklog_warnings" -gt 0 ]]; then
    echo "warning: $worklog_warnings work log(s) exceed compaction threshold (>${WORKLOG_MAX_LINES} lines or >${WORKLOG_MAX_KB}KB)" >&2
  fi
fi

# --- Post-deploy .gitignore safety check ---
# If a .gitignore exists, ensure SSoT artifacts are NOT being ignored.
GITIGNORE="$ROOT/.gitignore"
if [[ -f "$GITIGNORE" ]]; then
  gitignore_errors=0
  # These paths MUST be tracked in git for persistence
  for must_track in \
    '.agentcortex/context/current_state.md' \
    '.agentcortex/context/archive/' \
    '.agentcortex/specs/' \
    '.agentcortex/adr/'; do
    # Check if the exact pattern appears as an ignore line (not negated, not commented)
    if grep -x -F -q -- "$must_track" "$GITIGNORE"; then
      echo "error: .gitignore must NOT ignore persistent SSoT artifact: $must_track" >&2
      gitignore_errors=$((gitignore_errors + 1))
    fi
  done
  if [[ "$gitignore_errors" -gt 0 ]]; then
    echo "error: $gitignore_errors SSoT artifact(s) are gitignored — run deploy_brain.sh to fix" >&2
    exit 1
  fi
fi

echo "AgentCortex integrity check passed"
