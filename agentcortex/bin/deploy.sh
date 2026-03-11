#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CP_FLAG="${CP_FLAG:-}"
TARGET="${TARGET:-${1:-.}}"

echo "Deploying AgentCortex v3.6.0 (Namespaced Import Layout) to $TARGET..."

mkdir -p "$TARGET/.agent/rules"
mkdir -p "$TARGET/.agent/workflows"
mkdir -p "$TARGET/.agent/skills"
mkdir -p "$TARGET/.antigravity"
mkdir -p "$TARGET/.agents/skills"
mkdir -p "$TARGET/.claude/commands"
mkdir -p "$TARGET/.codex"
mkdir -p "$TARGET/codex/rules"
mkdir -p "$TARGET/.github/ISSUE_TEMPLATE"
mkdir -p "$TARGET/tools"
mkdir -p "$TARGET/docs/context/work"
mkdir -p "$TARGET/docs/context/archive"
mkdir -p "$TARGET/docs/specs"
mkdir -p "$TARGET/docs/adr"
mkdir -p "$TARGET/agentcortex/bin"
mkdir -p "$TARGET/agentcortex/tools"
mkdir -p "$TARGET/agentcortex/docs/guides"
mkdir -p "$TARGET/agentcortex/templates"

cp $CP_FLAG "$REPO_ROOT/AGENTS.md" "$TARGET/"
cp $CP_FLAG "$REPO_ROOT/CLAUDE.md" "$TARGET/"
[ -f "$REPO_ROOT/deploy_brain.sh" ] && cp $CP_FLAG "$REPO_ROOT/deploy_brain.sh" "$TARGET/" && chmod +x "$TARGET/deploy_brain.sh"
[ -f "$REPO_ROOT/deploy_brain.ps1" ] && cp $CP_FLAG "$REPO_ROOT/deploy_brain.ps1" "$TARGET/"
[ -f "$REPO_ROOT/deploy_brain.cmd" ] && cp $CP_FLAG "$REPO_ROOT/deploy_brain.cmd" "$TARGET/"
[ -f "$REPO_ROOT/tools/validate.sh" ] && cp $CP_FLAG "$REPO_ROOT/tools/validate.sh" "$TARGET/tools/" && chmod +x "$TARGET/tools/validate.sh"
[ -f "$REPO_ROOT/tools/validate.ps1" ] && cp $CP_FLAG "$REPO_ROOT/tools/validate.ps1" "$TARGET/tools/"
[ -f "$REPO_ROOT/tools/validate.cmd" ] && cp $CP_FLAG "$REPO_ROOT/tools/validate.cmd" "$TARGET/tools/"

[ -f "$REPO_ROOT/.antigravity/rules.md" ] && cp $CP_FLAG "$REPO_ROOT/.antigravity/rules.md" "$TARGET/.antigravity/"
[ -f "$REPO_ROOT/codex/rules/default.rules" ] && cp $CP_FLAG "$REPO_ROOT/codex/rules/default.rules" "$TARGET/codex/rules/"
cp $CP_FLAG "$REPO_ROOT/.agent/rules/engineering_guardrails.md" "$TARGET/.agent/rules/"
for f in "$REPO_ROOT"/.agent/workflows/*.md; do
  [ -f "$f" ] && cp $CP_FLAG "$f" "$TARGET/.agent/workflows/"
done

if [ -d "$REPO_ROOT/.agents/skills" ]; then
  cp -r "$REPO_ROOT/.agents/skills/"* "$TARGET/.agents/skills/" 2>/dev/null || true
  cp -r "$REPO_ROOT/.agents/skills/"* "$TARGET/.agent/skills/" 2>/dev/null || true
elif [ -d "$REPO_ROOT/.agent/skills" ]; then
  cp -r "$REPO_ROOT/.agent/skills/"* "$TARGET/.agent/skills/" 2>/dev/null || true
  cp -r "$REPO_ROOT/.agent/skills/"* "$TARGET/.agents/skills/" 2>/dev/null || true
fi

touch "$TARGET/.agent/skills/.gitkeep"
touch "$TARGET/.agents/skills/.gitkeep"
if [ -d "$TARGET/.agent/skills" ]; then
  cp -r "$TARGET/.agent/skills/"* "$TARGET/.agents/skills/" 2>/dev/null || true
fi

for f in deploy.sh deploy.ps1 validate.sh validate.ps1; do
  [ -f "$REPO_ROOT/agentcortex/bin/$f" ] && cp $CP_FLAG "$REPO_ROOT/agentcortex/bin/$f" "$TARGET/agentcortex/bin/"
done
[ -f "$TARGET/agentcortex/bin/deploy.sh" ] && chmod +x "$TARGET/agentcortex/bin/deploy.sh"
[ -f "$TARGET/agentcortex/bin/validate.sh" ] && chmod +x "$TARGET/agentcortex/bin/validate.sh"
[ -f "$REPO_ROOT/agentcortex/tools/audit_ai_paths.sh" ] && cp $CP_FLAG "$REPO_ROOT/agentcortex/tools/audit_ai_paths.sh" "$TARGET/agentcortex/tools/" && chmod +x "$TARGET/agentcortex/tools/audit_ai_paths.sh"

cp $CP_FLAG "$REPO_ROOT/docs/context/current_state.md" "$TARGET/docs/context/"
for f in "$REPO_ROOT"/docs/adr/*.md; do
  [ -f "$f" ] && cp $CP_FLAG "$f" "$TARGET/docs/adr/"
done
for f in \
  "$REPO_ROOT"/README*.md \
  "$REPO_ROOT"/AGENT_MODEL_GUIDE*.md \
  "$REPO_ROOT"/agentcortex/docs/AGENT_PHILOSOPHY*.md \
  "$REPO_ROOT"/agentcortex/docs/TESTING_PROTOCOL*.md \
  "$REPO_ROOT"/agentcortex/docs/CODEX_PLATFORM_GUIDE*.md \
  "$REPO_ROOT"/agentcortex/docs/PROJECT_EXAMPLES*.md \
  "$REPO_ROOT"/agentcortex/docs/CLAUDE_PLATFORM_GUIDE.md; do
  [ -f "$f" ] && cp $CP_FLAG "$f" "$TARGET/agentcortex/docs/"
done
for f in "$REPO_ROOT"/agentcortex/docs/guides/*.md; do
  [ -f "$f" ] && cp $CP_FLAG "$f" "$TARGET/agentcortex/docs/guides/"
done

if [ -d "$REPO_ROOT/.claude/commands" ]; then
  cp -r "$REPO_ROOT/.claude/commands/"* "$TARGET/.claude/commands/" 2>/dev/null || true
fi

GITIGNORE="$TARGET/.gitignore"
DOWNSTREAM_IGNORE_START="# AgentCortex Template - Downstream Ignore Defaults"
DOWNSTREAM_IGNORE_END="# End AgentCortex Template - Downstream Ignore Defaults"
LEGACY_IGNORE_START="# AI Brain OS - Agent System & Local Context"

write_downstream_ignore_block() {
    cat <<'EOT'
# AgentCortex Template - Downstream Ignore Defaults
docs/context/current_state.md
docs/context/work/
docs/context/archive/
docs/context/private/
.openrouter/
.claude-chat/
.cursor/
.antigravity/scratch/
# End AgentCortex Template - Downstream Ignore Defaults
EOT
}

strip_managed_ignore_blocks() {
    local source_file="$1"
    local output_file="$2"

    awk '
    BEGIN {
        managed[".agent/"] = 1
        managed[".agents/"] = 1
        managed[".antigravity/"] = 1
        managed[".claude/"] = 1
        managed[".codex/"] = 1
        managed["codex/"] = 1
        managed["AGENTS.md"] = 1
        managed["CLAUDE.md"] = 1
        managed["README.md"] = 1
        managed["README_zh-TW.md"] = 1
        managed["AGENT_MODEL_GUIDE.md"] = 1
        managed["AGENT_MODEL_GUIDE_zh-TW.md"] = 1
        managed["CHANGELOG.md"] = 1
        managed["CITATION.cff"] = 1
        managed["CONTRIBUTING.md"] = 1
        managed["docs/context/"] = 1
        managed["docs/context/current_state.md"] = 1
        managed["docs/context/work/"] = 1
        managed["docs/context/archive/"] = 1
        managed["docs/context/private/"] = 1
        managed["docs/AGENT_PHILOSOPHY.md"] = 1
        managed["docs/AGENT_PHILOSOPHY_zh-TW.md"] = 1
        managed["docs/CLAUDE_PLATFORM_GUIDE.md"] = 1
        managed["docs/CODEX_PLATFORM_GUIDE.md"] = 1
        managed["docs/CODEX_PLATFORM_GUIDE_zh-TW.md"] = 1
        managed["docs/PROJECT_EXAMPLES.md"] = 1
        managed["docs/PROJECT_EXAMPLES_zh-TW.md"] = 1
        managed["docs/TESTING_PROTOCOL.md"] = 1
        managed["docs/TESTING_PROTOCOL_zh-TW.md"] = 1
        managed["docs/guides/antigravity-v5-runtime.md"] = 1
        managed["docs/guides/audit-guardrails.md"] = 1
        managed["docs/guides/audit-guardrails_zh-TW.md"] = 1
        managed["docs/guides/migration.md"] = 1
        managed["docs/guides/migration_zh-TW.md"] = 1
        managed["docs/guides/multi-remote-workflow.md"] = 1
        managed["docs/guides/portable-minimal-kit.md"] = 1
        managed["docs/guides/token-governance.md"] = 1
        managed["docs/guides/token-governance_zh-TW.md"] = 1
        managed["docs/adr/ADR-001-vnext-self-managed-architecture.md"] = 1
        managed["tools/audit_ai_paths.sh"] = 1
        managed[".openrouter/"] = 1
        managed[".claude-chat/"] = 1
        managed[".cursor/"] = 1
        managed[".antigravity/scratch/"] = 1
    }

    /^# AgentCortex Template - Downstream Ignore Defaults$/ { skip = 1; next }
    /^# AI Brain OS - Agent System & Local Context$/ { skip = 1; next }
    /^# End AgentCortex Template - Downstream Ignore Defaults$/ { skip = 0; next }

    skip {
        if ($0 == "" || ($0 in managed)) { next }
        skip = 0
    }

    { print }
    ' "$source_file" > "$output_file"
}

echo ""
echo "Checking .gitignore..."
if [ ! -f "$GITIGNORE" ]; then
    touch "$GITIGNORE"
fi

TMP_STRIPPED_GITIGNORE="$(mktemp)"
TMP_NORMALIZED_GITIGNORE="$(mktemp)"

if grep -Eq "^(${DOWNSTREAM_IGNORE_START}|${LEGACY_IGNORE_START})$" "$GITIGNORE"; then
    echo "Replacing managed downstream ignore defaults in .gitignore..."
else
    echo "Adding AgentCortex downstream ignore defaults to .gitignore..."
fi

strip_managed_ignore_blocks "$GITIGNORE" "$TMP_STRIPPED_GITIGNORE"

awk '
{
    lines[NR] = $0
}
END {
    last = NR
    while (last > 0 && lines[last] == "") {
        last--
    }
    for (i = 1; i <= last; i++) {
        print lines[i]
    }
}
' "$TMP_STRIPPED_GITIGNORE" > "$TMP_NORMALIZED_GITIGNORE"

{
    if [ -s "$TMP_NORMALIZED_GITIGNORE" ]; then
        cat "$TMP_NORMALIZED_GITIGNORE"
        printf '\n\n'
    fi
    write_downstream_ignore_block
    printf '\n'
} > "$GITIGNORE"

rm -f "$TMP_STRIPPED_GITIGNORE" "$TMP_NORMALIZED_GITIGNORE"

echo ""
echo "AgentCortex v3.6.0 deployed successfully!"
echo ""
echo "Platform Entry Points Ready:"
echo "   .antigravity/rules.md  -> Google Antigravity"
echo "   codex/rules/           -> Codex Web/App"
echo "   CLAUDE.md              -> Claude (manual entry)"
echo "   AGENTS.md              -> Cross-platform entry"
echo "   agentcortex/bin/       -> Canonical AgentCortex implementations"
echo ""
echo "Git Safety:"
echo "   Managed AgentCortex ignore defaults cover runtime and local state only."
echo ""
echo "Next steps:"
echo "   1. Tell AI: 'Please run /bootstrap' to start"
echo "   2. AgentCortex reference docs are under agentcortex/docs/"