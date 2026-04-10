# AgentCortex Deploy Wrapper (PowerShell)
# Canonical source relocated to .agentcortex/bin/deploy.ps1
$scriptPath = Join-Path $PSScriptRoot '.agentcortex' 'bin' 'deploy.ps1'
& $scriptPath @args
