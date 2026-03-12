@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\agentcortex\bin\validate.ps1"
exit /b %errorlevel%