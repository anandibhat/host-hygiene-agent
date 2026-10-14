# Sets up a Windows Scheduled Task to run Host Hygiene daily automatically on your laptop.
param (
    [string]$Time = "09:00"
)

$TaskName = "HostHygieneDailyAudit"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Find Python binary
$LocalPy = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
if (-not (Test-Path $LocalPy)) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd -and ($cmd.Source -notlike "*WindowsApps*")) {
        $LocalPy = $cmd.Source
    } else {
        $LocalPy = "python.exe"
    }
}

$ScriptPath = Join-Path $ScriptDir "run_daily.py"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Setting Up Daily Host Hygiene Scheduled Task for Laptop" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Task Name:     $TaskName"
Write-Host " Scheduled Time:$Time Daily (with missed run catchup for laptops)"
Write-Host " Python Exec:   $LocalPy"
Write-Host " Target Script: $ScriptPath"
Write-Host ""

# 1. Action: Execute python run_daily.py in project directory
$Action = New-ScheduledTaskAction `
    -Execute $LocalPy `
    -Argument "`"$ScriptPath`"" `
    -WorkingDirectory $ScriptDir

# 2. Trigger: Daily at specified time
$DailyTrigger = New-ScheduledTaskTrigger -Daily -At $Time

# Also add logon trigger so it checks when laptop is booted/unlocked
$LogonTrigger = New-ScheduledTaskTrigger -AtLogon

# 3. Settings tailored specifically for laptops:
# - StartWhenAvailable: Catches up if laptop was asleep/closed at 9:00 AM
# - AllowStartIfOnBatteries: Runs even if unplugged
# - DontStopIfGoingOnBatteries: Continues if unplugged during run
$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

try {
    # Unregister existing task if present
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    # Register the new scheduled task for the current user
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger @($DailyTrigger) `
        -Settings $Settings `
        -Description "Performs daily host hygiene assessment and process triage." | Out-Null

    Write-Host "[SUCCESS] Scheduled task '$TaskName' registered successfully!" -ForegroundColor Green
    Write-Host " -> Runs every day at $Time." -ForegroundColor Green
    Write-Host " -> If your laptop is asleep or closed, it will automatically catch up when you open it." -ForegroundColor Green
    Write-Host " -> Daily reports and history will be saved to: $ScriptDir\daily_reports\" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to register task: $_" -ForegroundColor Red
    Write-Host "Try running this script as Administrator if standard user rights are restricted." -ForegroundColor Yellow
}
