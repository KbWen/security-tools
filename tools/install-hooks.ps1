# GhostCheck Hook Installer for Windows
# This script installs the pre-commit hook into the .git/hooks directory.

$hookSource = Join-Path $PSScriptRoot "pre-commit"
$hookTarget = Join-Path $PSScriptRoot "..\\.git\\hooks\\pre-commit"

if (-Not (Test-Path ".git")) {
    Write-Error "Error: Must run from project root."
    exit 1
}

Write-Host "🔧 Installing GhostCheck pre-commit hook..." -ForegroundColor Cyan

if (Test-Path $hookTarget) {
    Write-Host "⚠️  Existing pre-commit hook found. Overwriting..." -ForegroundColor Yellow
}

Copy-Item -Path $hookSource -Destination $hookTarget -Force

Write-Host "✅ Pre-commit hook installed successfully." -ForegroundColor Green
Write-Host "GhostCheck will now automatically scan for risks before every commit."
