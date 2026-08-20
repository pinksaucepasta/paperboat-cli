param(
  [Parameter(Mandatory=$true)][string]$Fixture,
  [string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$fixturePath = [IO.Path]::GetFullPath($Fixture)

if (-not (Test-Path $fixturePath) -or [IO.Path]::GetExtension($fixturePath) -ne '.exe') { throw 'fixture must be an existing absolute .exe' }
if (Get-Service -Name 'PaperboatHostd','PaperboatUpdated','PaperboatPreview-*' -ErrorAction SilentlyContinue) { throw 'doctor repair qualification requires no installed host runtime' }
$before = Get-CimInstance Win32_Service -Filter "Name='PaperboatSshd'"
if ($null -eq $before -or $before.State -ne 'Running' -or $before.StartMode -ne 'Auto') { throw 'PaperboatSshd must be healthy before repair qualification' }
$serviceExecutable = if ($before.PathName.StartsWith('"')) { $before.PathName.Split('"')[1] } else { $before.PathName.Split(' ')[0] }
if (-not [IO.Path]::IsPathRooted($serviceExecutable) -or -not (Test-Path -LiteralPath $serviceExecutable -PathType Leaf)) { throw 'PaperboatSshd wrapper executable is unavailable' }
$env:PAPERBOAT_SERVICE_EXECUTABLE = $serviceExecutable

try {
  Stop-Service PaperboatSshd -Force
  $savedPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $repairOutput = (& $fixturePath __runtime-service repair 2>&1 | Out-String).Trim()
  $repairExitCode = $LASTEXITCODE
  $ErrorActionPreference = $savedPreference
  if ($repairExitCode -ne 0) { throw ('doctor repair failed: ' + $repairOutput) }
  $after = Get-CimInstance Win32_Service -Filter "Name='PaperboatSshd'"
  if ($after.State -ne 'Running' -or $after.StartMode -ne 'Auto' -or $after.PathName -ne $before.PathName -or $after.StartName -ne $before.StartName) { throw 'doctor repair did not restore PaperboatSshd without changing its identity' }
  $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 38222 -ErrorAction SilentlyContinue)
  if ($listeners.Count -ne 2 -or @($listeners | Where-Object LocalAddress -eq '127.0.0.1').Count -ne 1 -or @($listeners | Where-Object LocalAddress -eq '::1').Count -ne 1) { throw 'doctor repair did not restore the loopback-only SSH listener pair' }
  $result = @{schema='paperboat.native-doctor-repair/v1';status='passed';service=$after.Name;account=$after.StartName;start_mode=$after.StartMode;path_preserved=$true;loopback_ipv4=$true;loopback_ipv6=$true;host_runtime_absent=$true} | ConvertTo-Json -Compress
  if ($ResultPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($ResultPath), $result, (New-Object Text.UTF8Encoding($false))) }
  Write-Output $result
} catch {
  if ($ResultPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($ResultPath), (@{schema='paperboat.native-doctor-repair/v1';status='failed';error=$_.Exception.Message} | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false))) }
  throw
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $fixturePath
  if ((Get-Service PaperboatSshd -ErrorAction SilentlyContinue).Status -ne 'Running') { Start-Service PaperboatSshd -ErrorAction SilentlyContinue }
}
