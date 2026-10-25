@echo off
title CIS Windows Server 2025 Benchmark v2.1.0 - Validator Launcher
set "SCRIPT_PATH=%~dp0cis-windows-server-2025-validator.ps1"

if not exist "%SCRIPT_PATH%" (
    echo [ERROR] Script file not found: "%SCRIPT_PATH%"
    echo Please make sure "cis-windows-server-2025-validator.ps1" is in the same folder as this .bat file.
    pause
    exit /b 1
)

echo Launching CIS Windows Server 2025 Validator with Administrator privileges...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%SCRIPT_PATH%\"'"
