param(
    [string]$Target = (Join-Path (Split-Path -Parent $PSScriptRoot) '.tmp_template_import_cleanup_smoke')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-PathString {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    return $Path
}

function Assert-PathState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$ShouldExist,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $exists = Test-Path -Path $Path -PathType Any
    if ($exists -ne $ShouldExist) {
        throw $Message
    }
}

function Assert-FileContainsLine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedLine,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $content = Get-Content -Path $Path
    if ($content -notcontains $ExpectedLine) {
        throw $Message
    }
}

$target = Normalize-PathString ([System.IO.Path]::GetFullPath((Normalize-PathString $Target)))

Assert-PathState -Path (Join-Path $target 'deploy_brain.sh') -ShouldExist $true -Message 'missing root deploy wrapper'
Assert-PathState -Path (Join-Path $target 'tools/validate.ps1') -ShouldExist $true -Message 'missing root validate wrapper'
Assert-PathState -Path (Join-Path $target 'agentcortex/bin/deploy.sh') -ShouldExist $true -Message 'missing canonical deploy implementation'
Assert-PathState -Path (Join-Path $target 'agentcortex/tools/audit_ai_paths.sh') -ShouldExist $true -Message 'missing canonical audit helper'
Assert-PathState -Path (Join-Path $target 'agentcortex/docs/CODEX_PLATFORM_GUIDE.md') -ShouldExist $true -Message 'missing namespaced platform doc'
Assert-PathState -Path (Join-Path $target 'agentcortex/docs/guides/token-governance.md') -ShouldExist $true -Message 'missing namespaced guide'
Assert-PathState -Path (Join-Path $target 'docs/context/current_state.md') -ShouldExist $true -Message 'missing fixed-anchor current state'
Assert-PathState -Path (Join-Path $target 'docs/adr/ADR-001-vnext-self-managed-architecture.md') -ShouldExist $true -Message 'missing fixed-anchor ADR'
Assert-PathState -Path (Join-Path $target 'docs/CODEX_PLATFORM_GUIDE.md') -ShouldExist $false -Message 'legacy root CODEX platform doc should not be deployed'
Assert-PathState -Path (Join-Path $target 'docs/guides/token-governance.md') -ShouldExist $false -Message 'legacy root guide should not be deployed'
Assert-PathState -Path (Join-Path $target 'tools/audit_ai_paths.sh') -ShouldExist $false -Message 'legacy root audit helper should not be deployed'

$gitignore = Join-Path $target '.gitignore'
Assert-PathState -Path $gitignore -ShouldExist $true -Message 'missing generated .gitignore'
Assert-FileContainsLine -Path $gitignore -ExpectedLine '# AgentCortex Template - Downstream Ignore Defaults' -Message 'missing downstream ignore block header'
Assert-FileContainsLine -Path $gitignore -ExpectedLine 'docs/context/current_state.md' -Message 'missing current_state ignore entry'
Assert-FileContainsLine -Path $gitignore -ExpectedLine '.antigravity/scratch/' -Message 'missing runtime scratch ignore entry'

Write-Output 'template import cleanup smoke test passed'
