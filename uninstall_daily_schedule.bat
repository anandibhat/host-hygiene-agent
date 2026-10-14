@echo off
cd /d "%~dp0"
echo ==========================================================
echo  Removing Daily Host Hygiene Audit Scheduled Task
echo ==========================================================
powershell -ExecutionPolicy Bypass -File "%~dp0uninstall_daily_schedule.ps1"
echo.
pause
