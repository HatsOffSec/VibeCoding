# Script: Find-WMIPersistence.ps1
# Purpose: Detect possible WMI event subscription persistence

Write-Host "Checking WMI Event Subscriptions for persistence techniques..." -ForegroundColor Cyan

# Get Event Filters (triggers)
$filters = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter |
    Select-Object Name, Query, EventNamespace

# Get Consumers (actions)
$consumers = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer |
    Select-Object Name, CommandLineTemplate, ExecutablePath

# Get Bindings (links between filter and consumer)
$bindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding |
    Select-Object Filter, Consumer

Write-Host "`n=== Event Filters (Triggers) ===" -ForegroundColor Yellow
if ($filters) { $filters | Format-Table -AutoSize } else { Write-Host "None found." -ForegroundColor Green }

Write-Host "`n=== Event Consumers (Payloads) ===" -ForegroundColor Yellow
if ($consumers) { $consumers | Format-Table -AutoSize } else { Write-Host "None found." -ForegroundColor Green }

Write-Host "`n=== Filter to Consumer Bindings (Links) ===" -ForegroundColor Yellow
if ($bindings) { $bindings | Format-Table -AutoSize } else { Write-Host "None found." -ForegroundColor Green }
