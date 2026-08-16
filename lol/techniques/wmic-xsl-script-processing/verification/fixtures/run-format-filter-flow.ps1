[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$FormatArgumentBase64,
  [Parameter(Mandatory = $true)][string]$WorkingDirectory,
  [Parameter(Mandatory = $true)][string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$FormatArgument = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($FormatArgumentBase64))
Set-Location -LiteralPath $WorkingDirectory
$markerPath = Join-Path $env:TEMP 'wmic-format-filter-marker.txt'
Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
$wmicPath = "$env:SystemRoot\System32\wbem\WMIC.exe"
$startUtc = [DateTime]::UtcNow.ToString('o')

$ErrorActionPreference = 'Continue'
$output = & $wmicPath 'os' 'get' 'Caption' $FormatArgument 2>&1 |
  ForEach-Object { $_.ToString() }
$exitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'

$endUtc = [DateTime]::UtcNow.ToString('o')
$markerCreated = Test-Path -LiteralPath $markerPath
$markerContent = if ($markerCreated) {
  (Get-Content -LiteralPath $markerPath -Raw).Trim()
} else {
  $null
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$integrityLine = (whoami.exe /groups | Select-String 'Mandatory Label').Line.Trim()

[ordered]@{
  start_utc = $startUtc
  end_utc = $endUtc
  account = $identity.Name
  is_administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  integrity = $integrityLine
  working_directory = (Get-Location).Path
  format_argument = $FormatArgument
  expected_native_argv = @('os', 'get', 'Caption', $FormatArgument)
  wmic_exit_code = $exitCode
  marker_path = $markerPath
  marker_created = $markerCreated
  marker_content = $markerContent
  output = @($output)
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
