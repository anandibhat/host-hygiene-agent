@echo off
cd /d "%~dp0"
echo ==========================================================
echo  Creating Desktop Shortcut for 1-Click Daily Audit
echo ==========================================================
powershell -ExecutionPolicy Bypass -File "%~dp0create_desktop_shortcut.ps1"
echo.
pause
