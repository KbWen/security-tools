Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-PathString {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    return $Path
}

function Join-NormalPath {
    param(
        [Parameter(Mandatory = $true)][string]$Base,
        [Parameter(Mandatory = $true)][string]$Child
    )
    return [System.IO.Path]::Combine((Normalize-PathString $Base), $Child)
}

function Assert-PathExists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Message,
        [switch]$Directory
    )
    $ok = if ($Directory) { Test-Path -Path $Path -PathType Container } else { Test-Path -Path $Path -PathType Leaf }
    if (-not $ok) {
        Write-Error $Message
        exit 1
    }
}

function Assert-FileContains {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $content = Get-Content -Raw -Encoding utf8 -Path $Path
    if ($content -notmatch $Pattern) {
        Write-Error $Message
        exit 1
    }
}

$scriptDir = Normalize-PathString ($PSScriptRoot)
if (-not $scriptDir) { $scriptDir = Normalize-PathString (Split-Path -Parent $PSCommandPath) }
if (-not $scriptDir) { $scriptDir = Normalize-PathString ((Get-Location).Path) }
$root = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($scriptDir, '..', '..'))

$platformDoc = Join-NormalPath $root 'agentcortex/docs/CODEX_PLATFORM_GUIDE.md'
$claudePlatformDoc = Join-NormalPath $root 'agentcortex/docs/CLAUDE_PLATFORM_GUIDE.md'
$examplesDoc = Join-NormalPath $root 'agentcortex/docs/PROJECT_EXAMPLES.md'
$projectAgentsFile = Join-NormalPath $root 'AGENTS.md'
$projectClaudeFile = Join-NormalPath $root 'CLAUDE.md'
$workflowsDir = Join-NormalPath $root '.agent/workflows'
$claudeCommandsDir = Join-NormalPath $root '.claude/commands'
$codexInstall = Join-NormalPath $root '.codex/INSTALL.md'
$codexRules = Join-NormalPath $root '.codex/rules/default.rules'
$rootDeploySh = Join-NormalPath $root 'deploy_brain.sh'
$rootDeployPs1 = Join-NormalPath $root 'deploy_brain.ps1'
$rootDeployCmd = Join-NormalPath $root 'deploy_brain.cmd'
$rootValidateSh = Join-NormalPath $root 'tools/validate.sh'
$rootValidatePs1 = Join-NormalPath $root 'tools/validate.ps1'
$rootValidateCmd = Join-NormalPath $root 'tools/validate.cmd'
$canonicalDeploySh = Join-NormalPath $root 'agentcortex/bin/deploy.sh'
$canonicalDeployPs1 = Join-NormalPath $root 'agentcortex/bin/deploy.ps1'
$canonicalValidateSh = Join-NormalPath $root 'agentcortex/bin/validate.sh'
$canonicalValidatePs1 = Join-NormalPath $root 'agentcortex/bin/validate.ps1'
$canonicalAuditSh = Join-NormalPath $root 'agentcortex/tools/audit_ai_paths.sh'
$textIntegrityCheckPs1 = Join-NormalPath $root 'tools/check_text_integrity.ps1'
$textIntegrityBaseline = Join-NormalPath $root 'tools/text_integrity_baseline.txt'

$requiredFiles = @(
    (Join-NormalPath $workflowsDir 'hotfix.md'),
    (Join-NormalPath $workflowsDir 'worktree-first.md'),
    (Join-NormalPath $workflowsDir 'new-feature.md'),
    (Join-NormalPath $workflowsDir 'medium-feature.md'),
    (Join-NormalPath $workflowsDir 'small-fix.md'),
    (Join-NormalPath $workflowsDir 'govern-docs.md'),
    (Join-NormalPath $workflowsDir 'handoff.md'),
    (Join-NormalPath $workflowsDir 'bootstrap.md'),
    (Join-NormalPath $workflowsDir 'plan.md'),
    (Join-NormalPath $workflowsDir 'implement.md'),
    (Join-NormalPath $workflowsDir 'review.md'),
    (Join-NormalPath $workflowsDir 'help.md'),
    (Join-NormalPath $workflowsDir 'test-skeleton.md'),
    (Join-NormalPath $workflowsDir 'commands.md')
)
$claudeRequiredFiles = @(
    (Join-NormalPath $claudeCommandsDir 'bootstrap.md'),
    (Join-NormalPath $claudeCommandsDir 'plan.md'),
    (Join-NormalPath $claudeCommandsDir 'implement.md'),
    (Join-NormalPath $claudeCommandsDir 'review.md'),
    (Join-NormalPath $claudeCommandsDir 'test.md'),
    (Join-NormalPath $claudeCommandsDir 'handoff.md'),
    (Join-NormalPath $claudeCommandsDir 'ship.md')
)
foreach ($file in $requiredFiles) { Assert-PathExists -Path $file -Message "missing required file: $file" }
foreach ($file in $claudeRequiredFiles) { Assert-PathExists -Path $file -Message "missing claude adapter file: $file" }
foreach ($file in @($platformDoc, $claudePlatformDoc, $examplesDoc, $projectAgentsFile, $projectClaudeFile, $rootDeploySh, $rootDeployPs1, $rootDeployCmd, $rootValidateSh, $rootValidatePs1, $rootValidateCmd, $canonicalDeploySh, $canonicalDeployPs1, $canonicalValidateSh, $canonicalValidatePs1, $canonicalAuditSh, $textIntegrityCheckPs1, $textIntegrityBaseline)) { Assert-PathExists -Path $file -Message "missing required file: $file" }
Assert-PathExists -Path $workflowsDir -Message "missing workflows dir: $workflowsDir" -Directory
Assert-PathExists -Path $claudeCommandsDir -Message "missing claude commands dir: $claudeCommandsDir" -Directory
Assert-PathExists -Path (Join-NormalPath $root '.agents/skills') -Message "missing codex skills dir: $(Join-NormalPath $root '.agents/skills')" -Directory
Assert-PathExists -Path (Join-NormalPath $root '.agent/skills') -Message "missing agent skills canonical dir: $(Join-NormalPath $root '.agent/skills')" -Directory
& $textIntegrityCheckPs1 -Root $root -BaselinePath $textIntegrityBaseline
$exitCode = if (Get-Variable LASTEXITCODE -ErrorAction SilentlyContinue) { $LASTEXITCODE } else { 0 }
if ($exitCode -ne 0) { exit $exitCode }
if (Test-Path -Path (Join-NormalPath $root 'tools/audit_ai_paths.sh') -PathType Leaf) {
    Write-Error "legacy audit helper should move under agentcortex/tools/: $(Join-NormalPath $root 'tools/audit_ai_paths.sh')"
    exit 1
}
Get-ChildItem -Path (Join-NormalPath $root '.agent/skills') -File | ForEach-Object {
    $skillName = $_.Name
    if ($skillName -eq '.gitkeep') { return }
    if ($_.Length -le 0) { Write-Error "empty skill metadata: $($_.FullName)"; exit 1 }
    $codexSkillPath = Join-NormalPath (Join-NormalPath $root '.agents/skills') $skillName
    Assert-PathExists -Path $codexSkillPath -Message "missing codex skill dir: $codexSkillPath" -Directory
    Assert-PathExists -Path (Join-NormalPath $codexSkillPath 'SKILL.md') -Message "missing skill definition: $(Join-NormalPath $codexSkillPath 'SKILL.md')"
}
$antigravityRules = Join-NormalPath $root '.antigravity/rules.md'
$legacyRules = Join-NormalPath $root '.agent/rules/rules.md'
Assert-PathExists -Path $antigravityRules -Message "missing antigravity rules: $antigravityRules"
Assert-PathExists -Path $legacyRules -Message "missing legacy rules copy: $legacyRules"
Assert-PathExists -Path $codexInstall -Message "missing codex install doc: $codexInstall"
Assert-FileContains -Path $legacyRules -Pattern '\.antigravity/rules\.md' -Message "legacy rules missing canonical redirect: $legacyRules"
Assert-FileContains -Path $legacyRules -Pattern 'legacy compatibility' -Message "legacy rules missing compatibility marker: $legacyRules"
Assert-FileContains -Path $antigravityRules -Pattern 'docker system prune -a' -Message "rules missing dangerous command: docker system prune -a in $antigravityRules"
Assert-FileContains -Path $antigravityRules -Pattern 'chown -R' -Message "rules missing dangerous command: chown -R in $antigravityRules"
Assert-FileContains -Path $antigravityRules -Pattern 'rollback' -Message "rules missing rollback reminder in $antigravityRules"
$activeCodexRules = Join-NormalPath $root 'codex/rules/default.rules'
if (-not (Test-Path -Path $activeCodexRules -PathType Leaf)) { $activeCodexRules = $codexRules }
if (Test-Path -Path $activeCodexRules -PathType Leaf) {
    Assert-FileContains -Path $activeCodexRules -Pattern 'prefix_rule\("' -Message "codex rules missing prefix_rule(): $activeCodexRules"
    Assert-FileContains -Path $activeCodexRules -Pattern 'docker system prune -a' -Message 'codex rules missing dangerous command: docker system prune -a'
    Assert-FileContains -Path $activeCodexRules -Pattern 'chown -R' -Message 'codex rules missing dangerous command: chown -R'
}
Assert-FileContains -Path $rootDeploySh -Pattern ([regex]::Escape('agentcortex/bin/deploy.sh')) -Message "deploy wrapper missing canonical reference: $rootDeploySh"
Assert-FileContains -Path $rootDeployPs1 -Pattern ([regex]::Escape("'agentcortex', 'bin', 'deploy.ps1'")) -Message "deploy wrapper missing canonical reference: $rootDeployPs1"
Assert-FileContains -Path $rootDeployCmd -Pattern ([regex]::Escape('agentcortex\bin\deploy.ps1')) -Message "deploy wrapper missing canonical reference: $rootDeployCmd"
Assert-FileContains -Path $rootValidateSh -Pattern ([regex]::Escape('agentcortex/bin/validate.sh')) -Message "validate wrapper missing canonical reference: $rootValidateSh"
Assert-FileContains -Path $rootValidatePs1 -Pattern ([regex]::Escape("'agentcortex', 'bin', 'validate.ps1'")) -Message "validate wrapper missing canonical reference: $rootValidatePs1"
Assert-FileContains -Path $rootValidateCmd -Pattern ([regex]::Escape('agentcortex\bin\validate.ps1')) -Message "validate wrapper missing canonical reference: $rootValidateCmd"
$worklogContractFiles = @(
    (Join-NormalPath $root 'AGENTS.md'),
    (Join-NormalPath $root '.agent/rules/engineering_guardrails.md'),
    (Join-NormalPath $root '.agent/rules/state_machine.md'),
    (Join-NormalPath $root '.agent/workflows/bootstrap.md'),
    (Join-NormalPath $root '.agent/workflows/plan.md'),
    (Join-NormalPath $root '.agent/workflows/handoff.md'),
    (Join-NormalPath $root '.agent/workflows/ship.md'),
    $platformDoc,
    (Join-NormalPath $root 'agentcortex/docs/NONLINEAR_SCENARIOS.md'),
    (Join-NormalPath $root 'agentcortex/docs/guides/antigravity-v5-runtime.md')
)
foreach ($file in $worklogContractFiles) {
    Assert-FileContains -Path $file -Pattern ([regex]::Escape('<worklog-key>')) -Message "worklog contract missing normalized key reference: $file"
    $content = Get-Content -Raw -Encoding utf8 -Path $file
    if ($content.Contains('docs/context/work/<branch-name>.md')) {
        Write-Error "stale branch-name worklog path contract: $file"
        exit 1
    }
    if ($content.Contains('docs/context/work/<branch>.md')) {
        Write-Error "stale raw branch worklog path contract: $file"
        exit 1
    }
}

$archiveContractFiles = @(
    (Join-NormalPath $root '.agent/workflows/handoff.md'),
    (Join-NormalPath $root 'agentcortex/docs/guides/token-governance.md'),
    (Join-NormalPath $root 'agentcortex/docs/guides/portable-minimal-kit.md')
)
foreach ($file in $archiveContractFiles) {
    Assert-FileContains -Path $file -Pattern ([regex]::Escape('<worklog-key>-<YYYYMMDD>')) -Message "archive worklog contract missing normalized key reference: $file"
    $content = Get-Content -Raw -Encoding utf8 -Path $file
    if ($content.Contains('docs/context/archive/work/<branch>-<YYYYMMDD>.md')) {
        Write-Error "stale archive branch worklog path contract: $file"
        exit 1
    }
}
$deployScript = $canonicalDeploySh
Assert-FileContains -Path $deployScript -Pattern ([regex]::Escape('LEGACY_IGNORE_START="# AI Brain OS - Agent System & Local Context"')) -Message 'deploy script missing legacy ignore marker support'
Assert-FileContains -Path $deployScript -Pattern ([regex]::Escape('strip_managed_ignore_blocks() {')) -Message 'deploy script missing managed ignore replacement helper'
Assert-FileContains -Path $deployScript -Pattern ([regex]::Escape('agentcortex/bin/')) -Message 'deploy script missing canonical namespace deployment path'
$deployBlock = New-Object System.Collections.Generic.List[string]
$capturing = $false
foreach ($line in Get-Content -Path $deployScript) {
    if ($line -eq '# AgentCortex Template - Downstream Ignore Defaults') { $capturing = $true }
    if ($capturing) { $deployBlock.Add($line) }
    if ($capturing -and $line -eq '# End AgentCortex Template - Downstream Ignore Defaults') { break }
}
if ($deployBlock.Count -eq 0) { Write-Error 'deploy ignore block missing from deploy script'; exit 1 }
foreach ($pattern in @('# AgentCortex Template - Downstream Ignore Defaults','docs/context/current_state.md','docs/context/work/','docs/context/archive/','docs/context/private/','.openrouter/','.claude-chat/','.cursor/','.antigravity/scratch/','# End AgentCortex Template - Downstream Ignore Defaults')) {
    if ($deployBlock -notcontains $pattern) { Write-Error "deploy ignore block missing pattern: $pattern"; exit 1 }
}
foreach ($pattern in @('.agent/', '.agents/', '.antigravity/', '.claude/', '.codex/', 'codex/', 'AGENTS.md', 'CLAUDE.md', 'README.md', 'docs/context/', 'tools/audit_ai_paths.sh')) {
    if ($deployBlock -contains $pattern) { Write-Error "deploy ignore block too broad for downstream repos: $pattern"; exit 1 }
}
foreach ($localizedFile in @(
    (Join-NormalPath $root 'README_zh-TW.md'),
    (Join-NormalPath $root 'agentcortex/docs/TESTING_PROTOCOL_zh-TW.md'),
    (Join-NormalPath $root 'agentcortex/docs/guides/audit-guardrails_zh-TW.md')
)) {
    Assert-PathExists -Path $localizedFile -Message "missing localized file: $localizedFile"
}
Assert-FileContains -Path (Join-NormalPath $root 'README_zh-TW.md') -Pattern '\u6D41\u7A0B\u9A45\u52D5.*AI Agent' -Message 'localized doc appears mojibaked or re-encoded: README_zh-TW.md'
Assert-FileContains -Path (Join-NormalPath $root 'agentcortex/docs/TESTING_PROTOCOL_zh-TW.md') -Pattern '\u6E2C\u8A66\u6559\u6230\u5B88\u5247' -Message 'localized doc appears mojibaked or re-encoded: agentcortex/docs/TESTING_PROTOCOL_zh-TW.md'
Assert-FileContains -Path (Join-NormalPath $root 'README.md') -Pattern ([regex]::Escape('Why AgentCortex?')) -Message 'english doc appears mojibaked or re-encoded: README.md'
Assert-FileContains -Path (Join-NormalPath $root 'agentcortex/docs/guides/audit-guardrails.md') -Pattern ([regex]::Escape('Test 1: Invisible Assistant Check (.gitignore Automation)')) -Message 'english doc appears mojibaked or re-encoded: agentcortex/docs/guides/audit-guardrails.md'
Assert-FileContains -Path (Join-NormalPath $root 'agentcortex/docs/guides/audit-guardrails_zh-TW.md') -Pattern '\u81EA\u52D5\u5316.*Shell Script' -Message 'localized doc appears mojibaked or re-encoded: agentcortex/docs/guides/audit-guardrails_zh-TW.md'
Write-Output 'AgentCortex integrity check passed'



