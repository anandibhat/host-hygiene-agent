@echo off
cd /d "%~dp0"
echo ==========================================================
echo  Registering Daily Host Hygiene Audit for Laptop
echo ==========================================================
powershell -ExecutionPolicy Bypass -File "%~dp0setup_daily_schedule.ps1"
echo.
pause
