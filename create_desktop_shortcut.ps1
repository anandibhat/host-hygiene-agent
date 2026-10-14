# Creates a Desktop Shortcut for 1-Click Daily Host Hygiene Scan
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Run Daily Host Hygiene Scan.lnk"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TargetBat = Join-Path $ScriptDir "run_desktop.bat"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetBat
$Shortcut.Arguments = ""
$Shortcut.WorkingDirectory = $ScriptDir
$Shortcut.Description = "Run Daily Host Hygiene and Process Triage Audit"
$Shortcut.IconLocation = "$env:SystemRoot\System32\imageres.dll,106"
$Shortcut.Save()

Write-Host "[SUCCESS] Updated Desktop Shortcut: $ShortcutPath" -ForegroundColor Green
Write-Host "Points to: $TargetBat" -ForegroundColor Cyan
