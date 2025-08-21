<# 
.SYNOPSIS
  Enumerate common Windows autostart/persistence locations (ASEPs) used by malware.

.DESCRIPTION
  Prints readable, grouped output for:
    - Run / RunOnce (HKLM/HKCU, incl. Wow6432Node)
    - Startup folders (All Users / Current User)
    - Winlogon tweaks (Shell, Userinit, etc.)
    - AppInit_DLLs (and LoadAppInit_DLLs)
    - IFEO Debuggers
    - Services (Auto-start)
    - Scheduled Tasks (non-Microsoft by default; PS5.1-safe)
    - WMI Event Consumers / Filters / Bindings (root\subscription)

.NOTES
  Run in an elevated prompt for best coverage.
#>

# ------------------ Options (toggle as needed) ------------------
# Include Microsoft's built-in scheduled tasks? (noisy)
$IncludeMicrosoftTasks = $false
# Include disabled tasks/services where applicable?
$IncludeDisabled = $false
# ---------------------------------------------------------------

# Visual helpers
function Write-Section {
  param([string]$Title)
  Write-Host ""
  Write-Host ("=" * ($Title.Length + 4)) -ForegroundColor Cyan
  Write-Host ("= $Title =") -ForegroundColor Cyan
  Write-Host ("=" * ($Title.Length + 4)) -ForegroundColor Cyan
}
function Out-NiceTable {
  param([Parameter(ValueFromPipeline=$true)]$InputObject)
  begin { $buf = @() }
  process { $buf += $InputObject }
  end { if ($buf -and $buf.Count -gt 0) { $buf | Format-Table -AutoSize } }
}

# Registry Run/RunOnce
function Get-RunKeyItems {
  $keys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" # rare "Run"
  )

  foreach ($key in $keys) {
    if (Test-Path $key) {
      try {
        $item = Get-ItemProperty -Path $key -ErrorAction Stop
        $props = $item.PSObject.Properties | Where-Object { $_.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider' }
        foreach ($p in $props) {
          $val = $p.Value
          if ($null -ne $val -and $val.ToString().Trim()) {
            [PSCustomObject]@{
              Location = $key
              Name     = $p.Name
              Command  = $val.ToString()
            }
          }
        }
      } catch {}
    }
  }
}

# Startup folders
function Get-StartupFolders {
  $paths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
  )
  foreach ($p in $paths) {
    if (Test-Path $p) {
      Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
          Folder  = $p
          Name    = $_.Name
          Target  = $_.FullName
        }
      }
    }
  }
}

# Winlogon tweaks
function Get-WinlogonSettings {
  $paths = @(
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
  )
  $interesting = @("Shell","Userinit","VMApplet","Taskman")
  foreach ($key in $paths) {
    if (Test-Path $key) {
      foreach ($name in $interesting) {
        try {
          $val = (Get-ItemProperty -Path $key -Name $name -ErrorAction Stop).$name
          if ($null -ne $val -and "$val".Trim()) {
            [PSCustomObject]@{
              Hive     = $key
              Value    = $name
              Data     = "$val"
            }
          }
        } catch {}
      }
    }
  }
}

# AppInit DLLs
function Get-AppInitDLLs {
  $key = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
  if (Test-Path $key) {
    $prop = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      Location        = $key
      AppInit_DLLs    = "$($prop.AppInit_DLLs)"
      LoadAppInitDLLs = "$($prop.LoadAppInit_DLLs)"
    }
  }
}

# IFEO debugger hijacks
function Get-IFEO {
  $root = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
  if (Test-Path $root) {
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $dbg = (Get-ItemProperty -Path $_.PsPath -Name "Debugger" -ErrorAction Stop).Debugger
        if ($dbg) {
          [PSCustomObject]@{
            Executable = $_.PSChildName
            Debugger   = "$dbg"
            Location   = $_.PSPath
          }
        }
      } catch {}
    }
  }
}

# Services (Auto-start)
function Get-ServicesAuto {
  $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $_.StartMode -eq 'Auto' -and ($IncludeDisabled -or $_.State -ne 'Stopped' -or $_.Started -eq $true)
  }
  $svcs | Sort-Object Name | ForEach-Object {
    [PSCustomObject]@{
      Name      = $_.Name
      Display   = $_.DisplayName
      StartMode = $_.StartMode
      State     = $_.State
      Path      = $_.PathName
    }
  }
}

# Scheduled Tasks (PS5.1-safe; handles null Triggers/Actions)
function Get-NonMicrosoftTasks {
  $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
  if (-not $tasks) { return }

  foreach ($t in $tasks) {
    if (-not $IncludeMicrosoftTasks -and $t.TaskPath -like "\Microsoft\Windows\*") { continue }
    if (-not $IncludeDisabled -and $t.State -eq 'Disabled') { continue }

    # Actions
    $actions = @()
    if ($t.Actions) {
      foreach ($a in $t.Actions) {
        try {
          if ($a.Execute) {
            $arg = ""
            if ($a.Arguments) { $arg = " " + $a.Arguments }
            $actions += (($a.Execute + $arg).Trim())
          } elseif ($a.ClassId) {
            $actions += ("[ComHandler] " + $a.ClassId)
          } else {
            $actions += ($a | Out-String).Trim()
          }
        } catch {
          $actions += "<unreadable action>"
        }
      }
    }

    # Triggers
    $triggerStrings = @()
    if ($t.Triggers) {
      foreach ($tr in $t.Triggers) {
        try {
          $name = $tr.GetType().Name
          switch ($name) {
            'MSFT_TaskBootTrigger'                { $triggerStrings += 'Boot'; continue }
            'MSFT_TaskLogonTrigger'               { $triggerStrings += 'Logon'; continue }
            'MSFT_TaskDailyTrigger'               { $triggerStrings += 'Daily'; continue }
            'MSFT_TaskWeeklyTrigger'              { $triggerStrings += 'Weekly'; continue }
            'MSFT_TaskTimeTrigger'                { $triggerStrings += 'Time'; continue }
            'MSFT_TaskEventTrigger'               { $triggerStrings += 'Event'; continue }
            'MSFT_TaskIdleTrigger'                { $triggerStrings += 'Idle'; continue }
            'MSFT_TaskRegistrationTrigger'        { $triggerStrings += 'OnRegister'; continue }
            'MSFT_TaskSessionStateChangeTrigger'  { $triggerStrings += 'SessionChange'; continue }
            default {
              try { $triggerStrings += ($tr.ToString()) } catch { $triggerStrings += "<trigger>" }
            }
          }
        } catch {
          $triggerStrings += "<unreadable trigger>"
        }
      }
    }

    # Author (safe stringify)
    $authorStr = ""
    if ($t.Author) { $authorStr = [string]$t.Author }

    [PSCustomObject]@{
      TaskPath = $t.TaskPath + $t.TaskName
      State    = $t.State
      Triggers = ($triggerStrings -join "; ")
      Actions  = ($actions -join " | ")
      Author   = $authorStr
    }
  }
}

# WMI event-consumer persistence (root\subscription)
function Get-WMIEventPersistence {
  $ns = "root\subscription"
  $result = @()

  try {
    $filters = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop
    foreach ($f in $filters) {
      $result += [PSCustomObject]@{
        Type   = "EventFilter"
        Name   = $f.Name
        Query  = $f.Query
        Target = $f.TargetNamespace
      }
    }
  } catch {}

  try {
    $consumers = Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction Stop
    foreach ($c in $consumers) {
      $result += [PSCustomObject]@{
        Type    = "CmdLineConsumer"
        Name    = $c.Name
        Command = $c.CommandLineTemplate
        RunAs   = $c.RunInteractively
      }
    }
  } catch {}

  try {
    $bindings = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop
    foreach ($b in $bindings) {
      $result += [PSCustomObject]@{
        Type     = "FilterToConsumer"
        Filter   = $b.Filter
        Consumer = $b.Consumer
      }
    }
  } catch {}

  $result
}

# ------------------ Execution & Output ------------------

Write-Section "Registry Run / RunOnce Entries"
$runItems = @(Get-RunKeyItems)
if ($runItems.Count -gt 0) { $runItems | Out-NiceTable } else { Write-Host "No Run/RunOnce entries found." -ForegroundColor DarkGray }

Write-Section "Startup Folders"
$startup = @(Get-StartupFolders)
if ($startup.Count -gt 0) { $startup | Out-NiceTable } else { Write-Host "No startup files found." -ForegroundColor DarkGray }

Write-Section "Winlogon (Shell / Userinit / etc.)"
$wl = @(Get-WinlogonSettings)
if ($wl.Count -gt 0) { $wl | Out-NiceTable } else { Write-Host "No Winlogon values of interest found." -ForegroundColor DarkGray }

Write-Section "AppInit_DLLs"
$appinit = @(Get-AppInitDLLs)
if ($appinit.Count -gt 0) { $appinit | Out-NiceTable } else { Write-Host "No AppInit values found." -ForegroundColor DarkGray }

Write-Section "IFEO (Image File Execution Options) Debuggers"
$ifeo = @(Get-IFEO)
if ($ifeo.Count -gt 0) { $ifeo | Out-NiceTable } else { Write-Host "No IFEO Debugger entries found." -ForegroundColor DarkGray }

Write-Section "Services (Auto-Start)"
$svcs = @(Get-ServicesAuto)
if ($svcs.Count -gt 0) { $svcs | Out-NiceTable } else { Write-Host "No auto-start services found (based on current filters)." -ForegroundColor DarkGray }

Write-Section "Scheduled Tasks"
$tasks = @(Get-NonMicrosoftTasks)
if ($tasks.Count -gt 0) { $tasks | Out-NiceTable } else { 
  if ($IncludeMicrosoftTasks) {
    Write-Host "No scheduled tasks found." -ForegroundColor DarkGray
  } else {
    Write-Host "No non-Microsoft tasks found. Set `$IncludeMicrosoftTasks = `$true to show all." -ForegroundColor DarkGray
  }
}

Write-Section "WMI Event Consumers / Filters / Bindings"
$wmi = @(Get-WMIEventPersistence)
if ($wmi.Count -gt 0) { $wmi | Out-NiceTable } else { Write-Host "No WMI persistence artifacts found (root\subscription)." -ForegroundColor DarkGray }

Write-Host ""
Write-Host "Tip: run elevated for best coverage. Investigate anything launching from Temp/AppData, user-writable dirs, or odd paths." -ForegroundColor Yellow
