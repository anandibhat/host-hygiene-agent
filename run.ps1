# PowerShell runner for Host Hygiene Agent
$ErrorActionPreference = "Stop"

# Prioritize the real Python binary installed in LocalAppData over the WindowsApps stub
$localPy = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
if (Test-Path $localPy) {
    $pythonCmd = $localPy
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $cmdPath = (Get-Command python).Source
    if ($cmdPath -like "*WindowsApps*") {
        # Check standard user path
        $userPy = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
        if (Test-Path $userPy) {
            $pythonCmd = $userPy
        } else {
            $pythonCmd = "python"
        }
    } else {
        $pythonCmd = "python"
    }
} else {
    $pythonCmd = "python"
}

# Run the host hygiene agent with all passed arguments
& $pythonCmd "$PSScriptRoot\run_agent.py" @args
