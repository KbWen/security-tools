param(
    [string]$Target = '.'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-PathString {
    param([string]$Path)
    if ($Path -and $Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    return $Path
}

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $PSCommandPath }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$scriptDir = Normalize-PathString $scriptDir
$canonical = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($scriptDir, 'agentcortex', 'bin', 'deploy.ps1'))

if (-not (Test-Path -Path $canonical -PathType Leaf)) {
    Write-Error "cannot find canonical deploy script: $canonical"
    exit 1
}

& $canonical -Target $Target
$exitCode = if (Get-Variable LASTEXITCODE -ErrorAction SilentlyContinue) { $LASTEXITCODE } else { 0 }
exit $exitCode