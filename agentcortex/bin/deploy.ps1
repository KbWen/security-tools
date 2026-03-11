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

function Resolve-BashLauncher {
    $bashCmd = Get-Command bash -ErrorAction SilentlyContinue
    if ($bashCmd) { return $bashCmd.Source }

    foreach ($candidate in @(
        'C:\Program Files\Git\bin\bash.exe',
        'C:\Program Files\Git\usr\bin\bash.exe',
        'C:\Program Files (x86)\Git\bin\bash.exe'
    )) {
        if (Test-Path -Path $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $PSCommandPath }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$scriptDir = Normalize-PathString $scriptDir
$bashScript = [System.IO.Path]::Combine($scriptDir, 'deploy.sh')

if (-not (Test-Path -Path $bashScript -PathType Leaf)) {
    Write-Error "cannot find canonical deploy script: $bashScript"
    exit 1
}

$bashLauncher = Resolve-BashLauncher
if (-not $bashLauncher) {
    Write-Error 'bash is not installed. Install Git Bash or WSL, then rerun deploy_brain.ps1.'
    exit 1
}

& $bashLauncher $bashScript $Target
exit $LASTEXITCODE