param([Parameter(Mandatory=$true)][string]$Fixture)
$ErrorActionPreference = 'Stop'
$fixturePath = [IO.Path]::GetFullPath($Fixture)
$programDataRoot = 'C:\ProgramData\Paperboat'
$installRoot = 'C:\Program Files\Paperboat'
$configPath = Join-Path $programDataRoot 'runtime-install.json'
$planPath = Join-Path $programDataRoot 'native-preview-e2e.json'
$tokenPath = Join-Path $programDataRoot 'hostd.token'
$stateRoot = Join-Path $programDataRoot 'native-preview-e2e-state'
$reportPath = Join-Path $stateRoot 'report.ndjson'
$runID = 'e2e-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$testUserName = 'pbe2e' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$testUserCreated = $false
$programDataExisted = Test-Path $programDataRoot
$originalProgramDataACL = if ($programDataExisted) { Get-Acl $programDataRoot } else { $null }

function Remove-TestService([string]$Name) {
  $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $service) { return }
  if ($service.Status -ne 'Stopped') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
  & sc.exe delete $Name | Out-Null
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  while ((Get-Service -Name $Name -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { throw "service cleanup failed: $Name" }
}

function Remove-TestDefinitions([string]$Root) {
  Get-ChildItem -LiteralPath (Join-Path $programDataRoot 'services') -Filter 'PaperboatPreview-*.json' -ErrorAction SilentlyContinue | ForEach-Object {
    $definition = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
    if (@($definition.arguments) -notcontains $Root) { throw "refusing to remove an unrelated preview declaration: $($_.FullName)" }
    Remove-Item -Force -LiteralPath $_.FullName
  }
}

$existing = @(Get-Service -Name 'PaperboatHostd','PaperboatUpdated','PaperboatPreview-*' -ErrorAction SilentlyContinue)
$existingDefinitions = @(Get-ChildItem -LiteralPath (Join-Path $programDataRoot 'services') -Filter 'PaperboatPreview-*.json' -ErrorAction SilentlyContinue)
if ($existing.Count -ne 0 -or $existingDefinitions.Count -ne 0 -or (Test-Path $configPath) -or (Test-Path $installRoot)) { throw 'native preview E2E requires empty Paperboat hostd/update/preview slots' }
if (-not (Test-Path $fixturePath) -or [IO.Path]::GetExtension($fixturePath) -ne '.exe') { throw 'fixture must be an existing absolute .exe' }

try {
  $accountCredential = ConvertTo-SecureString (([Guid]::NewGuid().ToString('N')) + 'aA1!') -AsPlainText -Force
  $owner = New-LocalUser -Name $testUserName -Password $accountCredential -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
  $testUserCreated = $true
  $ownerSID = $owner.SID.Value
  $ownerName = "$env:COMPUTERNAME\$testUserName"
  $workspaceRoot = "C:\Users\$testUserName"
  New-Item -ItemType Directory -Force -Path $programDataRoot,$stateRoot | Out-Null
  & icacls.exe $programDataRoot /grant "*$ownerSID`:(RX)" | Out-Null
  & icacls.exe $stateRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$ownerSID`:(OI)(CI)F" | Out-Null
  $utf8NoBom = New-Object Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($planPath, (@{Schema='paperboat.native-preview-e2e/v1';StateRoot=$stateRoot;ReportPath=$reportPath;RunID=$runID;Port=32123;HoldAfterComplete=$false} | ConvertTo-Json -Compress), $utf8NoBom)
  & icacls.exe $planPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "*$ownerSID`:F" | Out-Null
  $runtimeCurrent = Join-Path $installRoot 'releases\runtime-current\paperboat-runtime.exe'
  New-Item -ItemType Directory -Force -Path (Split-Path $runtimeCurrent) | Out-Null
  Copy-Item -Force $fixturePath $runtimeCurrent
  [byte[]]$token = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($token) } finally { $rng.Dispose() }
  [IO.File]::WriteAllBytes($tokenPath,$token)
  $artifact = @{schema='paperboat.tuf-target/v1';kind='pb';version='2026.08.19.1';platform='windows';architecture='amd64';repository_url='https://updates.invalid';target_path='pb-windows-amd64'}
  [IO.File]::WriteAllText($configPath, (@{schema='paperboat.windows-runtime-install/v1';owner_sid=$ownerSID;user=$ownerName;state_root=$stateRoot;workspace_root=$workspaceRoot;control_url='https://control.invalid';machine_id='machine_native_preview_e2e';token_file=$tokenPath;installed_at=[DateTime]::UtcNow.ToString('o');committed=$true;artifact=$artifact} | ConvertTo-Json -Depth 5 -Compress), $utf8NoBom)
  & icacls.exe $configPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "*$ownerSID`:F" | Out-Null
  $tokenACL = Get-Acl $tokenPath
  $tokenACL.SetSecurityDescriptorSddlForm("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$ownerSID)")
  Set-Acl -Path $tokenPath -AclObject $tokenACL
  & icacls.exe $runtimeCurrent /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "*$ownerSID`:RX" | Out-Null
  $binaryCommand = '"' + $runtimeCurrent + '" __runtime-hostd'
  New-Service -Name 'PaperboatHostd' -BinaryPathName $binaryCommand -DisplayName 'PaperboatHostd' -Description 'Paperboat native preview broker qualification' -StartupType Automatic | Out-Null
  try { Start-Service 'PaperboatHostd' } catch {
    $direct = (& $runtimeCurrent __runtime-hostd 2>&1 | Out-String).Trim()
    throw "PaperboatHostd failed to start; direct entry result: $direct"
  }
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  while ([DateTime]::UtcNow -lt $deadline) {
    if ((Test-Path $reportPath) -and ((Get-Content -Raw $reportPath) -match '"stage":"(complete|failed)"')) { break }
    Start-Sleep -Milliseconds 200
  }
  if (-not (Test-Path $reportPath)) { throw 'hostd owner did not create an E2E report' }
  $events = @(Get-Content $reportPath | ForEach-Object { $_ | ConvertFrom-Json })
  $ownerEvent = @($events | Where-Object stage -eq 'hostd_owner')[-1]
  $previewEvent = @($events | Where-Object stage -eq 'preview_owner')[-1]
  $complete = @($events | Where-Object stage -eq 'complete').Count
  if ($ownerEvent.sid -ne $ownerSID -or $ownerEvent.elevated -or $ownerEvent.session_id -ne 0 -or $previewEvent.sid -ne $ownerSID -or $previewEvent.elevated -or $complete -ne 1) {
    throw ('owner/broker/preview qualification assertions failed: ' + ($events | ConvertTo-Json -Compress))
  }
  $hostd = Get-CimInstance Win32_Service -Filter "Name='PaperboatHostd'"
  if ($hostd.StartName -ne 'LocalSystem') { throw 'PaperboatHostd is not registered as LocalSystem' }
  $stopDeadline = [DateTime]::UtcNow.AddSeconds(20)
  while ((Get-Service PaperboatHostd).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $stopDeadline) { Start-Sleep -Milliseconds 100 }
  if ((Get-Service PaperboatHostd).Status -ne 'Stopped') { throw 'PaperboatHostd did not stop after its owner workload completed' }
  Start-Service PaperboatHostd
  $restartDeadline = [DateTime]::UtcNow.AddSeconds(90)
  do {
    $events = @(Get-Content $reportPath | ForEach-Object { $_ | ConvertFrom-Json })
    if (@($events | Where-Object stage -eq 'failed').Count -ne 0) { throw ('PaperboatHostd restart failed: ' + ($events | ConvertTo-Json -Compress)) }
    if (@($events | Where-Object stage -eq 'complete').Count -eq 2) { break }
    Start-Sleep -Milliseconds 200
  } while ([DateTime]::UtcNow -lt $restartDeadline)
  if (@($events | Where-Object stage -eq 'complete').Count -ne 2) { throw 'PaperboatHostd restart qualification timed out' }
  $stopDeadline = [DateTime]::UtcNow.AddSeconds(20)
  while ((Get-Service PaperboatHostd).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $stopDeadline) { Start-Sleep -Milliseconds 100 }
  if ((Get-Service PaperboatHostd).Status -ne 'Stopped') { throw 'PaperboatHostd did not stop after restart qualification' }
  $holdPlan = Get-Content -Raw $planPath | ConvertFrom-Json
  $holdPlan.HoldAfterComplete = $true
  [IO.File]::WriteAllText($planPath, ($holdPlan | ConvertTo-Json -Compress), $utf8NoBom)
  Start-Service PaperboatHostd
  $ownerDeadline = [DateTime]::UtcNow.AddSeconds(45)
  do {
    $events = @(Get-Content $reportPath | ForEach-Object { $_ | ConvertFrom-Json })
    if (@($events | Where-Object stage -eq 'hostd_owner').Count -eq 3 -and (Get-Service PaperboatHostd).Status -eq 'Running') { break }
    Start-Sleep -Milliseconds 200
  } while ([DateTime]::UtcNow -lt $ownerDeadline)
  if (@($events | Where-Object stage -eq 'hostd_owner').Count -ne 3 -or (Get-Service PaperboatHostd).Status -ne 'Running') { throw 'PaperboatHostd did not enter the owner-deletion qualification state' }
  Remove-LocalUser -Name $testUserName
  $testUserCreated = $false
  $deletionDeadline = [DateTime]::UtcNow.AddSeconds(45)
  while ((Get-Service PaperboatHostd).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deletionDeadline) { Start-Sleep -Milliseconds 250 }
  if ((Get-Service PaperboatHostd).Status -ne 'Stopped') { throw 'PaperboatHostd did not stop after enrolled owner deletion' }
  $replacementCredential = ConvertTo-SecureString (([Guid]::NewGuid().ToString('N')) + 'aA1!') -AsPlainText -Force
  $replacement = New-LocalUser -Name $testUserName -Password $replacementCredential -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
  $testUserCreated = $true
  if ($replacement.SID.Value -eq $ownerSID) { throw 'replacement account unexpectedly reused the enrolled owner SID' }
  try { Start-Service PaperboatHostd -ErrorAction Stop } catch { }
  $replacementDeadline = [DateTime]::UtcNow.AddSeconds(20)
  while ((Get-Service PaperboatHostd).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $replacementDeadline) { Start-Sleep -Milliseconds 200 }
  if ((Get-Service PaperboatHostd).Status -ne 'Stopped') { throw 'PaperboatHostd accepted a replacement account with a different SID' }
  Remove-LocalUser -Name $testUserName
  $testUserCreated = $false
  Write-Output (@{status='passed';owner_sid=$ownerSID;replacement_sid=$replacement.SID.Value;hostd_account=$hostd.StartName;owner_session_id=$ownerEvent.session_id;owner_elevated=$ownerEvent.elevated;preview_elevated=$previewEvent.elevated;restart_count=2;owner_deletion_detected=$true;sid_replacement_rejected=$true;events=$events.Count} | ConvertTo-Json -Compress)
} finally {
  Get-Service -Name 'PaperboatPreview-*' -ErrorAction SilentlyContinue | ForEach-Object { Remove-TestService $_.Name }
  Remove-TestDefinitions $stateRoot
  Remove-TestService 'PaperboatHostd'
  Remove-TestService 'PaperboatUpdated'
  Remove-Item -Force -ErrorAction SilentlyContinue $configPath,$planPath,$tokenPath
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $stateRoot,$installRoot
  Remove-Item -Force -ErrorAction SilentlyContinue $fixturePath
  if ($programDataExisted -and $null -ne $originalProgramDataACL -and (Test-Path $programDataRoot)) { Set-Acl -Path $programDataRoot -AclObject $originalProgramDataACL }
  if ($testUserCreated) { Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue }
}
