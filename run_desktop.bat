@echo off
title Host Hygiene Daily Scan
color 0A
cd /d "%~dp0"

echo ================================================================================
echo               HOST HYGIENE DAILY SCAN - STARTING AUDIT
echo ================================================================================
echo.

:: 1. Prioritize real installed Python 3.12
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" run_daily.py
    goto :finish
)

:: 2. Try py launcher
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    py run_daily.py
    goto :finish
)

:: 3. Try python on PATH
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    python run_daily.py
    goto :finish
)

color 0C
echo [!] Error: Python executable not found on this system.
echo Please ensure Python is installed in %LOCALAPPDATA%\Programs\Python\Python312.
echo.

:finish
echo.
echo ================================================================================
echo Scan complete! You can review past reports in the 'daily_reports' folder.
echo Press any key to close this window...
echo ================================================================================
pause >nul
