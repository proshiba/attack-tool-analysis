[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$FlowId,
  [Parameter(Mandatory = $true)][string]$UserName,
  [Parameter(Mandatory = $true)][ValidateSet('standard', 'administrator')][string]$Privilege,
  [Parameter(Mandatory = $true)][string]$PasswordBase64,
  [Parameter(Mandatory = $true)][string]$FormatArgumentBase64,
  [Parameter(Mandatory = $true)][string]$WorkingDirectory,
  [Parameter(Mandatory = $true)][string]$StylesheetDestination
)

$ErrorActionPreference = 'Stop'
$password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PasswordBase64))
$FormatArgument = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($FormatArgumentBase64))
$root = 'C:\lab\format-filter'
$resultPath = Join-Path $root 'result.json'
$collectionPath = Join-Path $root 'collection'
$runnerPath = Join-Path $root 'run-format-filter-flow.ps1'
$fixturePath = Join-Path $root 'wmic-format-filter-test.xsl'

New-Item -ItemType Directory -Path $root, $WorkingDirectory, (Split-Path -Parent $StylesheetDestination) -Force | Out-Null
$existingUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($existingUser) { Remove-LocalUser -Name $UserName }
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name $UserName -Password $securePassword -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
Add-LocalGroupMember -Group 'Performance Log Users' -Member $UserName
if ($Privilege -eq 'administrator') {
  Add-LocalGroupMember -Group 'Administrators' -Member $UserName
}

& icacls.exe $root /grant "${UserName}:(OI)(CI)M" /T /C | Out-Null
& icacls.exe $WorkingDirectory /grant "${UserName}:(OI)(CI)M" /T /C | Out-Null
Copy-Item -LiteralPath $fixturePath -Destination $StylesheetDestination -Force

$argumentList = @(
  '-NoLogo', '-NoProfile', '-NonInteractive',
  '-ExecutionPolicy', 'Bypass',
  '-File', $runnerPath,
  '-FormatArgumentBase64', $FormatArgumentBase64,
  '-WorkingDirectory', $WorkingDirectory,
  '-ResultPath', $resultPath
)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (($argumentList | ForEach-Object {
  if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
}) -join ' ')
$trigger = New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes(5))
$runLevel = if ($Privilege -eq 'administrator') { 'Highest' } else { 'Limited' }
$taskName = "WmicFormatFilter-$FlowId"
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
  -User "$env:COMPUTERNAME\$UserName" -Password $password -RunLevel $runLevel -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

$deadline = [DateTime]::UtcNow.AddMinutes(2)
do {
  Start-Sleep -Milliseconds 250
  $state = (Get-ScheduledTask -TaskName $taskName).State
} while (-not (Test-Path -LiteralPath $resultPath) -and [DateTime]::UtcNow -lt $deadline)
if (-not (Test-Path -LiteralPath $resultPath)) {
  $lastResult = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
  throw "runner did not create result.json; state=$state last_result=$lastResult"
}

$result = $null
do {
  try {
    $result = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop | ConvertFrom-Json
  }
  catch {
    Start-Sleep -Milliseconds 250
  }
} while ($null -eq $result -and [DateTime]::UtcNow -lt $deadline)
if ($null -eq $result) { throw 'result.json never became readable' }
do {
  $state = (Get-ScheduledTask -TaskName $taskName).State
  if ($state -ne 'Ready') { Start-Sleep -Milliseconds 250 }
} while ($state -ne 'Ready' -and [DateTime]::UtcNow -lt $deadline)
if ($state -ne 'Ready') { throw "task did not return to Ready; state=$state" }
& C:\Tools\collect-run.ps1 -StartUtc $result.start_utc -EndUtc $result.end_utc -OutDir $collectionPath
$markerCopy = Join-Path $root 'marker.txt'
if ($result.marker_created) { Copy-Item -LiteralPath $result.marker_path -Destination $markerCopy -Force }

$summary = [ordered]@{
  flow_id = $FlowId
  requested_privilege = $Privilege
  stylesheet_destination = $StylesheetDestination
  launcher = 'Task Scheduler'
  scheduled_task_last_result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
  result = $result
}
$summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $root 'summary.json') -Encoding UTF8
Compress-Archive -Path (Join-Path $root '*') -DestinationPath "C:\lab\$FlowId.zip" -Force
