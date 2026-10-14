# Removes the daily Host Hygiene scheduled task
$TaskName = "HostHygieneDailyAudit"

try {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[SUCCESS] Removed scheduled task '$TaskName'." -ForegroundColor Green
    } else {
        Write-Host "[INFO] Scheduled task '$TaskName' was not found." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Could not remove task: $_" -ForegroundColor Red
}
