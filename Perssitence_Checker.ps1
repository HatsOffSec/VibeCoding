function Get-NonMicrosoftTasks {
  $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
  if (-not $tasks) { return }

  foreach ($t in $tasks) {
    if (-not $IncludeMicrosoftTasks -and $t.TaskPath -like "\Microsoft\Windows\*") { continue }
    if (-not $IncludeDisabled -and $t.State -eq 'Disabled') { continue }

    # Safely render actions
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

    # Safely render triggers (some tasks have none)
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

    # Author: stringify safely so $null becomes empty string
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
