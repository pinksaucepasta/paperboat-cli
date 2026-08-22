param(
  [string]$Fixture,
  [switch]$Resume
)

$ErrorActionPreference = 'Stop'
$programDataRoot = 'C:\ProgramData\Paperboat'
$installRoot = 'C:\Program Files\Paperboat'
$statePath = Join-Path $programDataRoot 'native-preview-reboot-state.json'
$planPath = Join-Path $programDataRoot 'native-preview-e2e.json'
$configPath = Join-Path $programDataRoot 'runtime-install.json'
$tokenPath = Join-Path $programDataRoot 'hostd.token'
$stateRoot = Join-Path $programDataRoot 'native-preview-reboot-state'
$reportPath = Join-Path $stateRoot 'report.ndjson'
$resultPath = 'C:\Users\Public\paperboat-preview-reboot-result.json'
$taskName = 'PaperboatNativePreviewRebootQualification'
$utf8NoBom = New-Object Text.UTF8Encoding($false)

function Get-TextSHA256([string]$Text) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant()) } finally { $sha.Dispose() }
}

function Get-ManagedSshSnapshot {
  $sshRoot = Join-Path $programDataRoot 'ssh'
  $files = if (Test-Path $sshRoot) { @(Get-ChildItem -LiteralPath $sshRoot -Recurse -Force | Where-Object { $_.FullName -notlike (Join-Path $sshRoot 'logs\*') } | Sort-Object FullName | ForEach-Object {
    $item = $_
    [ordered]@{path=$item.FullName.Substring($sshRoot.Length);directory=$item.PSIsContainer;length=if($item.PSIsContainer){0}else{$item.Length};sddl=(Get-Acl -LiteralPath $item.FullName).Sddl;sha256=if($item.PSIsContainer){''}else{(Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()}}
  }) } else { @() }
  $service = Get-CimInstance Win32_Service -Filter "Name='PaperboatSshd'" -ErrorAction SilentlyContinue
  $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Paperboat|OpenSSH' } | Sort-Object Name | ForEach-Object { [ordered]@{name=$_.Name;display_name=$_.DisplayName;enabled=[string]$_.Enabled;direction=[string]$_.Direction;action=[string]$_.Action;profile=[string]$_.Profile} })
  return Get-TextSHA256 (([ordered]@{files=$files;service=if($null -eq $service){$null}else{[ordered]@{name=$service.Name;state=$service.State;start_mode=$service.StartMode;start_name=$service.StartName;path=$service.PathName}};firewall=$rules} | ConvertTo-Json -Depth 8 -Compress))
}

function Remove-TestService([string]$Name) {
  $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $service) { return }
  if ($service.Status -ne 'Stopped') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
  & sc.exe delete $Name | Out-Null
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
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

function Remove-QualificationState($State) {
  Get-Service -Name 'PaperboatPreview-*' -ErrorAction SilentlyContinue | ForEach-Object { Remove-TestService $_.Name }
  Remove-TestDefinitions $stateRoot
  Remove-TestService 'PaperboatHostd'
  Remove-TestService 'PaperboatUpdated'
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item -Force -ErrorAction SilentlyContinue $configPath,$planPath,$tokenPath,$statePath
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $stateRoot,$installRoot
  if ($null -ne $State -and $State.program_data_existed -and $State.program_data_sddl -and (Test-Path $programDataRoot)) {
    $acl = Get-Acl $programDataRoot
    $acl.SetSecurityDescriptorSddlForm([string]$State.program_data_sddl)
    Set-Acl -Path $programDataRoot -AclObject $acl
  }
  if ($null -ne $State -and $State.test_user) { Remove-LocalUser -Name ([string]$State.test_user) -ErrorAction SilentlyContinue }
  if ($null -ne $State -and $State.fixture) { Remove-Item -Force -ErrorAction SilentlyContinue ([string]$State.fixture) }
}

if ($Resume) {
  if (-not (Test-Path $statePath)) { throw 'native preview reboot qualification state is missing' }
  $state = Get-Content -Raw $statePath | ConvertFrom-Json
  $cleaned = $false
  try {
    $deadline = [DateTime]::UtcNow.AddSeconds(180)
    do {
      $events = if (Test-Path $reportPath) { @(Get-Content $reportPath | ForEach-Object { $_ | ConvertFrom-Json }) } else { @() }
      if (@($events | Where-Object stage -eq 'failed').Count -ne 0) { throw ('post-reboot hostd failed: ' + ($events | ConvertTo-Json -Compress)) }
      if (@($events | Where-Object stage -eq 'complete').Count -eq 1) { break }
      Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $owners = @($events | Where-Object stage -eq 'hostd_owner')
    $previews = @($events | Where-Object stage -eq 'preview_owner')
    if ($owners.Count -ne 1 -or $previews.Count -lt 3 -or @($events | Where-Object stage -eq 'complete').Count -ne 1) { throw ('post-reboot lifecycle evidence is incomplete: ' + ($events | ConvertTo-Json -Compress)) }
    if ($owners[0].sid -ne $state.owner_sid -or $owners[0].elevated -or $owners[0].session_id -ne 0) { throw 'post-reboot owner token is not the logged-out enrolled owner in session 0' }
    if (@($previews | Where-Object { $_.sid -ne $state.owner_sid -or $_.elevated }).Count -ne 0) { throw 'post-reboot preview worker token mismatch' }
    $hostd = Get-CimInstance Win32_Service -Filter "Name='PaperboatHostd'"
    $bootedAt = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
    if ($hostd.StartName -ne 'LocalSystem' -or $hostd.StartMode -ne 'Auto' -or $bootedAt -le ([DateTimeOffset]::Parse([string]$state.prepared_at)).UtcDateTime) { throw 'PaperboatHostd did not recover through a newer real Windows boot' }
    Remove-QualificationState $state
    $cleaned = $true
    if ((Get-Acl $programDataRoot).Sddl -ne $state.program_data_sddl) { throw 'ProgramData Paperboat root ACL changed across reboot qualification' }
    if ((Get-ManagedSshSnapshot) -ne $state.managed_ssh_snapshot) { throw 'Paperboat managed SSH state changed across reboot qualification' }
    $remaining = @(Get-Service -Name 'PaperboatHostd','PaperboatUpdated','PaperboatPreview-*' -ErrorAction SilentlyContinue)
    if ($remaining.Count -ne 0) { throw 'qualification services remain after cleanup' }
    $result = [ordered]@{schema='paperboat.native-preview-reboot-result/v1';status='passed';prepared_at=$state.prepared_at;booted_at=$bootedAt.ToString('o');owner_sid=$state.owner_sid;owner_session_id=$owners[0].session_id;owner_elevated=$owners[0].elevated;preview_elevated=$false;hostd_account=$hostd.StartName;hostd_start_mode=$hostd.StartMode;events=$events.Count;managed_ssh_unchanged=$true;program_data_acl_unchanged=$true;cleanup_verified=$true}
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Compress), $utf8NoBom)
  } catch {
    if (-not $cleaned) { Remove-QualificationState $state }
    [IO.File]::WriteAllText($resultPath, (@{schema='paperboat.native-preview-reboot-result/v1';status='failed';error=$_.Exception.Message} | ConvertTo-Json -Compress), $utf8NoBom)
    throw
  }
  exit 0
}

if (-not $Fixture) { throw '-Fixture is required when preparing the reboot qualification' }
$fixturePath = [IO.Path]::GetFullPath($Fixture)
$existing = @(Get-Service -Name 'PaperboatHostd','PaperboatUpdated','PaperboatPreview-*' -ErrorAction SilentlyContinue)
$existingDefinitions = @(Get-ChildItem -LiteralPath (Join-Path $programDataRoot 'services') -Filter 'PaperboatPreview-*.json' -ErrorAction SilentlyContinue)
if ($existing.Count -ne 0 -or $existingDefinitions.Count -ne 0 -or (Test-Path $configPath) -or (Test-Path $installRoot) -or (Test-Path $statePath)) { throw 'native preview reboot qualification requires empty hostd/update/preview slots' }
if (-not (Test-Path $fixturePath) -or [IO.Path]::GetExtension($fixturePath) -ne '.exe') { throw 'fixture must be an existing absolute .exe' }

$programDataExisted = Test-Path $programDataRoot
$originalProgramDataSDDL = if ($programDataExisted) { (Get-Acl $programDataRoot).Sddl } else { '' }
$testUserName = 'pbe2e' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$state = $null
$managedSshSnapshot = Get-ManagedSshSnapshot
try {
  Remove-Item -Force -ErrorAction SilentlyContinue $resultPath
  $accountCredential = ConvertTo-SecureString (([Guid]::NewGuid().ToString('N')) + 'aA1!') -AsPlainText -Force
  $owner = New-LocalUser -Name $testUserName -Password $accountCredential -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
  $ownerSID = $owner.SID.Value
  $state = [ordered]@{schema='paperboat.native-preview-reboot-state/v1';prepared_at=[DateTimeOffset]::UtcNow.ToString('o');owner_sid=$ownerSID;test_user=$testUserName;fixture=$fixturePath;program_data_existed=$programDataExisted;program_data_sddl=$originalProgramDataSDDL;managed_ssh_snapshot=$managedSshSnapshot}
  $runID = 'e2e-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
  New-Item -ItemType Directory -Force -Path $programDataRoot,$stateRoot | Out-Null
  & icacls.exe $programDataRoot /grant "*$ownerSID`:(RX)" | Out-Null
  & icacls.exe $stateRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$ownerSID`:(OI)(CI)F" | Out-Null
  [IO.File]::WriteAllText($planPath, (@{Schema='paperboat.native-preview-e2e/v1';StateRoot=$stateRoot;ReportPath=$reportPath;RunID=$runID;Port=32123} | ConvertTo-Json -Compress), $utf8NoBom)
  & icacls.exe $planPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "*$ownerSID`:F" | Out-Null
  $runtimeCurrent = Join-Path $installRoot 'releases\runtime-current\paperboat-runtime.exe'
  New-Item -ItemType Directory -Force -Path (Split-Path $runtimeCurrent) | Out-Null
  Copy-Item -Force $fixturePath $runtimeCurrent
  [byte[]]$token = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($token) } finally { $rng.Dispose() }
  [IO.File]::WriteAllBytes($tokenPath,$token)
  $architecture = if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
  $artifact = @{schema='paperboat.tuf-target/v1';kind='pb';version='2026.08.19.1';platform='windows';architecture=$architecture;repository_url='https://updates.invalid';target_path="pb-windows-$architecture"}
  [IO.File]::WriteAllText($configPath, (@{schema='paperboat.windows-runtime-install/v1';owner_sid=$ownerSID;user="$env:COMPUTERNAME\$testUserName";state_root=$stateRoot;workspace_root="C:\Users\$testUserName";control_url='https://control.invalid';machine_id='machine_native_preview_reboot_e2e';token_file=$tokenPath;installed_at=[DateTime]::UtcNow.ToString('o');committed=$true;artifact=$artifact} | ConvertTo-Json -Depth 5 -Compress), $utf8NoBom)
  & icacls.exe $configPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "*$ownerSID`:F" | Out-Null
  $tokenACL = Get-Acl $tokenPath
  $tokenACL.SetSecurityDescriptorSddlForm("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$ownerSID)")
  Set-Acl -Path $tokenPath -AclObject $tokenACL
  & icacls.exe $runtimeCurrent /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "*$ownerSID`:RX" | Out-Null
  New-Service -Name 'PaperboatHostd' -BinaryPathName ('"' + $runtimeCurrent + '" __runtime-hostd') -DisplayName 'PaperboatHostd' -Description 'Paperboat native preview reboot qualification' -StartupType Automatic | Out-Null
  [IO.File]::WriteAllText($statePath, ($state | ConvertTo-Json -Compress), $utf8NoBom)
  & icacls.exe $statePath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
  $scriptPath = $MyInvocation.MyCommand.Path
  $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $scriptPath + '" -Resume')
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  Restart-Computer -Force
} catch {
  Remove-QualificationState $state
  throw
}
