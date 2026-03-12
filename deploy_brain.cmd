@echo off
setlocal

if exist "%~dp0agentcortex\bin\deploy.ps1" goto run_ps1
if exist "%~dp0agentcortex\bin\deploy.sh" goto run_bash

echo [ERROR] Canonical deploy implementation not found under agentcortex\bin.
exit /b 1

:run_ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0agentcortex\bin\deploy.ps1" %*
exit /b %errorlevel%

:run_bash
where bash >nul 2>nul
if errorlevel 1 goto no_bash
bash "%~dp0agentcortex\bin\deploy.sh" %*
exit /b %errorlevel%

:no_bash
echo [ERROR] bash is not installed. Install Git Bash or WSL, or run the PowerShell deployer.
exit /b 1