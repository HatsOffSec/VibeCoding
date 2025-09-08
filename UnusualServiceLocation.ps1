# Script: Find-UnusualServicePaths.ps1
# Purpose: Identify services with executables running outside of standard Windows or Program Files directories

# Get all services with WMI to pull the PathName
$services = Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State

# Define "normal" base paths
$validPaths = @(
    "C:\Windows",
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Program Files",
    "C:\Program Files (x86)"
)

Write-Host "Checking services for unusual executable paths..." -ForegroundColor Cyan
Write-Host ""

# Collect unusual services
$unusual = foreach ($svc in $services) {
    if (![string]::IsNullOrWhiteSpace($svc.PathName)) {

        # --- FIX: Correctly parse the executable path ---
        $exe = $svc.PathName.Trim()

        # If quoted, take inside the quotes
        if ($exe -match '^"(.*?)"') {
            $exe = $matches[1]
        }
        else {
            # Otherwise, take everything up to ".exe"
            if ($exe -match '^(.*?\.exe)') {
                $exe = $matches[1]
            }
        }

        try {
            $fullPath = [System.IO.Path]::GetFullPath($exe)
        } catch {
            continue
        }

        $isNormal = $false
        foreach ($valid in $validPaths) {
            if ($fullPath -like "$valid*") {
                $isNormal = $true
                break
            }
        }

        if (-not $isNormal) {
            [PSCustomObject]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                StartMode   = $svc.StartMode
                State       = $svc.State
                Executable  = $fullPath
            }
        }
    }
}

# Show results neatly if any were found
if ($unusual) {
    $unusual | Format-Table -AutoSize
} else {
    Write-Host "No unusual service paths found." -ForegroundColor Green
}
