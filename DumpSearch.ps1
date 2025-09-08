# Script: Query-CrashDumps.ps1
# Purpose: List Windows crash dump and related log files with size + creation time

Write-Host "Querying crash dump and log locations..." -ForegroundColor Cyan

# Common dump/log file locations
$targets = @(
    "C:\Windows\MEMORY.DMP",
    "C:\Windows\Minidump\*.dmp",
    "C:\Windows\LiveKernelReports\*.dmp",
    "C:\Windows\LiveKernelReports\*.etl",
    "C:\DumpStack.log",
    "C:\DumpStack.log.tmp"
)

$results = foreach ($pattern in $targets) {
    $path = Split-Path $pattern -Parent
    $filter = Split-Path $pattern -Leaf
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter $filter -Force -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                File     = $_.FullName
                SizeMB   = "{0:N2}" -f ($_.Length / 1MB)
                Created  = $_.CreationTime
            }
        }
    }
}

if ($results) {
    Write-Host "`n=== Crash Dumps and Logs Found ===" -ForegroundColor Yellow
    $results | Sort-Object Created -Descending | Format-Table -AutoSize
} else {
    Write-Host "`nNo crash dump or log files found." -ForegroundColor Green
}
