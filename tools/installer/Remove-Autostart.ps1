$ErrorActionPreference = 'Stop'
$installedExe = Join-Path $PSScriptRoot 'VPSLink.exe'
$legacyExe = Join-Path $PSScriptRoot 'ThingsNotFun-Link.exe'
# Only tasks for this exact installed copy; portable copies and other VPNs are untouched.
foreach ($task in Get-ScheduledTask -TaskName 'ThingsNotFun-Link-S-1-*' -ErrorAction SilentlyContinue) {
    if ($task.Actions.Count -eq 1 -and $task.Actions[0].Execute -in @($installedExe,$legacyExe) -and $task.Actions[0].Arguments -eq '--startup') {
        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
    }
}
