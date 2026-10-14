@echo off
setlocal
cd /d "%~dp0"

:: 1. Prioritize real installed Python 3.12 over WindowsApps alias
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" run_agent.py %*
    goto :end
)

:: 2. Try py launcher
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    py run_agent.py %*
    goto :end
)

:: 3. Try python on PATH
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    python run_agent.py %*
    goto :end
)

echo [!] Python executable not found. Please ensure Python is installed.

:end
echo.
echo Press any key to close this window...
pause >nul
