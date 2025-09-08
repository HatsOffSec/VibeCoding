# Script: Clean-CrashDumpsInteractive.ps1
# Purpose: Search for crash dumps/logs and ask the user before deleting each file

Write-Host "Scanning for crash dump and log files..." -ForegroundColor Cyan

# Common dump/log file locations
$targets = @(
    "C:\Windows\MEMORY.DMP",
    "C:\Windows\Minidump\*.dmp",
    "C:\Windows\LiveKernelReports\*.dmp",
    "C:\Windows\LiveKernelReports\*.etl",
    "C:\DumpStack.log",
    "C:\DumpStack.log.tmp"
)

$found = @()
foreach ($pattern in $targets) {
    $path = Split-Path $pattern -Parent
    $filter = Split-Path $pattern -Leaf
    if (Test-Path $path) {
        $items = Get-ChildItem -Path $path -Filter $filter -Force -ErrorAction SilentlyContinue
        if ($items) { $found += $items }
    }
}

if (-not $found) {
    Write-Host "`nNo crash dump or log files found." -ForegroundColor Green
    exit
}

Write-Host "`n=== Crash Dumps and Logs Found ===" -ForegroundColor Yellow
$found | Select-Object FullName,
    @{Name="SizeMB";Expression={"{0:N2}" -f ($_.Length / 1MB)}},
    CreationTime |
    Sort-Object CreationTime -Descending |
    Format-Table -AutoSize

# Interactive deletion
foreach ($file in $found) {
    $sizeMB = "{0:N2}" -f ($file.Length / 1MB)
    $answer = Read-Host "`nDo you want to delete '$($file.FullName)' (Size: $sizeMB MB, Created: $($file.CreationTime))? (Y/N)"
    if ($answer -match '^[Yy]$') {
        if (Test-Path -LiteralPath $file.FullName) {
            try {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($file.FullName)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to delete: $($file.FullName) - $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "Skipped: $($file.FullName) - File no longer exists." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipped: $($file.FullName)" -ForegroundColor Yellow
    }
}
