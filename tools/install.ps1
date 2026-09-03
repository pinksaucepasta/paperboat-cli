<#
  Paperboat's native Windows bootstrap. The only downloaded executable is the
  final pb.exe for this architecture. It is verified against current.json and
  then asks that same executable to perform the elevated installation.
#>
$ErrorActionPreference = 'Stop'

$server = if ($env:PAPERBOAT_SERVER) { [string]$env:PAPERBOAT_SERVER } else { 'https://api.pprbt.dev' }
$metadataUrl = if ($env:PAPERBOAT_RELEASE_METADATA_URL) { [string]$env:PAPERBOAT_RELEASE_METADATA_URL } else { "$server/current.json" }
$token = [string]$env:PAPERBOAT_ENROLLMENT_TOKEN
$name = [string]$env:PAPERBOAT_MACHINE_NAME
$freshEnrollment = -not [string]::IsNullOrWhiteSpace($token)
$requestedVersion = if ($env:PAPERBOAT_VERSION) { [string]$env:PAPERBOAT_VERSION } else { 'latest' }
$repo = if ($env:PAPERBOAT_GITHUB_REPOSITORY) { [string]$env:PAPERBOAT_GITHUB_REPOSITORY } else { 'pinksaucepasta/paperboat-cli' }

if ($server -notmatch '^https://') { throw 'Paperboat server URL must use HTTPS.' }
if ($metadataUrl -notmatch '^https://') { throw 'Paperboat release metadata URL must use HTTPS.' }
if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Paperboat release repository is invalid.' }
if ($freshEnrollment -and $token -notmatch '^[0-9A-Z]{26}$') { throw 'Paperboat enrollment token is invalid.' }

$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } elseif ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'X64') { 'amd64' } else { throw 'Paperboat supports only Windows AMD64 and ARM64.' }
$asset = "pb-windows-$arch.exe"
$current = (Invoke-WebRequest -UseBasicParsing -Uri $metadataUrl -TimeoutSec 30).Content | ConvertFrom-Json
$version = [string]$current.version
if ([string]$current.schema -ne 'paperboat.release-current/v1' -or $version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$' -or [string]$current.repository -ne $repo) {
  throw 'Paperboat current.json is invalid.'
}
if ($requestedVersion -ne 'latest' -and $requestedVersion -ne $version) { throw 'Requested Paperboat version is not the current release.' }

$assetProperty = $current.assets.PSObject.Properties[$asset]
if ($null -eq $assetProperty) { throw "Paperboat current.json has no metadata for $asset." }
$assetMetadata = $assetProperty.Value
if ([string]$assetMetadata.platform -ne 'windows' -or [string]$assetMetadata.architecture -ne $arch -or [string]$assetMetadata.format -ne 'pe' -or [string]$assetMetadata.sha256 -notmatch '^[0-9a-f]{64}$' -or [int64]$assetMetadata.length -lt 1) {
  throw "Paperboat current.json metadata for $asset is invalid."
}
$expectedUrl = "https://github.com/$repo/releases/download/$version/$asset"
if ([string]$assetMetadata.url -ne $expectedUrl) { throw 'Paperboat release asset URL is not an immutable GitHub release URL.' }

$dir = Join-Path $env:TEMP ('Paperboat\bootstrap-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$download = Join-Path $dir $asset
$partial = "$download.download"
$installedPb = Join-Path ${env:ProgramFiles} 'Paperboat\bin\pb.exe'

function Download-ReleaseFile([string]$Url, [string]$Output) {
  for ($attempt = 1; $attempt -le 4; $attempt++) {
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
    try {
      $curl = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue
      if ($null -ne $curl) {
        & $curl.Source '--silent' '--show-error' '--location' '--fail' '--retry' '1' '--retry-all-errors' '--connect-timeout' '20' '--max-time' '300' '--output' $partial $Url
        if ($LASTEXITCODE -ne 0) { throw "curl exit $LASTEXITCODE" }
      } else {
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $partial -TimeoutSec 300 -MaximumRedirection 5
      }
      Move-Item -LiteralPath $partial -Destination $Output -Force
      return
    } catch {
      Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
      if ($attempt -eq 4) { throw "Download failed for $Url after $attempt attempts: $($_.Exception.Message)" }
      Start-Sleep -Seconds ($attempt * 2)
    }
  }
}

Download-ReleaseFile ([string]$assetMetadata.url) $download
$file = Get-Item -LiteralPath $download
if ([int64]$file.Length -ne [int64]$assetMetadata.length) { throw "Paperboat release asset length verification failed for $asset." }
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $download).Hash.ToLowerInvariant()
if ($actual -ne [string]$assetMetadata.sha256) { throw "Paperboat release asset digest verification failed for $asset." }

Unblock-File -LiteralPath $download -ErrorAction SilentlyContinue

$trustedBootstrapDirectory = Join-Path ${env:ProgramFiles} 'Paperboat\bootstrap'
function Stage-TrustedBootstrap([string]$Source) {
  New-Item -ItemType Directory -Force -Path $trustedBootstrapDirectory | Out-Null
  $staged = Join-Path $trustedBootstrapDirectory ('pb-' + [guid]::NewGuid().ToString('N') + '.exe')
  Copy-Item -LiteralPath $Source -Destination $staged -Force
  Unblock-File -LiteralPath $staged -ErrorAction SilentlyContinue
  return $staged
}

function Assert-InstalledVersion([string]$Path, [string]$ExpectedVersion) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  $capture = [IO.Path]::GetTempFileName()
  $captureError = "$capture.err"
  try {
    $probe = Start-Process -FilePath $Path -ArgumentList '--version' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $capture -RedirectStandardError $captureError
    if ($probe.ExitCode -ne 0) { return $false }
    $output = ((Get-Content -LiteralPath $capture -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $captureError -Raw -ErrorAction SilentlyContinue))
  } catch {
    return $false
  } finally {
    Remove-Item -LiteralPath $capture,$captureError -Force -ErrorAction SilentlyContinue
  }
  $versionMatches = [regex]::Matches($output, '(Version[\t ]+[0-9A-Za-z._-]+)')
  return $versionMatches.Count -eq 1 -and $versionMatches[0].Groups[1].Value -eq ("Version " + $ExpectedVersion)
}

if (-not (Assert-InstalledVersion $download $version)) {
  throw "Downloaded Paperboat release does not report version $version."
}

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-InteractiveUac {
  # A UAC broker needs a desktop that can display and receive the consent
  # prompt. OpenSSH and service/CI sessions are deliberately rejected here so
  # an unattended install fails immediately instead of waiting forever on a
  # prompt nobody can answer.
  if (-not [System.Environment]::UserInteractive) { return $false }
  if (-not [string]::IsNullOrWhiteSpace([string]$env:SSH_CONNECTION) -or
      -not [string]::IsNullOrWhiteSpace([string]$env:SSH_CLIENT) -or
      -not [string]::IsNullOrWhiteSpace([string]$env:SSH_TTY)) {
    return $false
  }
  try {
    return (Get-Process -Id $PID -ErrorAction Stop).SessionId -ne 0
  } catch {
    return $false
  }
}

function Wait-InstallerProcess($Process, [string]$Operation) {
  if ($null -eq $Process) { throw "$Operation did not return a process handle." }
  # Start-Process -Wait waits the entire process tree. WaitForExit waits only
  # the elevated installer root, so a detached helper cannot hold the outer
  # bootstrap open after the installer has reported its exit code.
  if (-not $Process.WaitForExit(1200000)) {
    try { $Process.Kill() } catch { }
    if (-not $Process.WaitForExit(5000)) {
      throw "$Operation exceeded the 20 minute limit and could not be stopped."
    }
    throw "$Operation exceeded the 20 minute limit."
  }
  return [int]$Process.ExitCode
}

function Assert-InstalledRelease([string]$Path, [string]$ExpectedVersion, [string]$ExpectedHash) {
  if (-not (Assert-InstalledVersion $Path $ExpectedVersion)) { return $false }
  try {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLowerInvariant()
    return $hash -eq $ExpectedHash
  } catch {
    return $false
  }
}

function Invoke-FreshPairRollback {
  # The pair command runs in the original user's process, after __install has
  # crossed the machine replacement boundary. Roll back both scopes when that
  # final step fails. The elevated payload derives fixed Paperboat paths; it
  # never accepts a caller-provided deletion root.
  foreach ($statePath in @(
    (Join-Path $env:LOCALAPPDATA 'Paperboat'),
    (Join-Path $env:APPDATA 'Paperboat')
  )) {
    Remove-Item -LiteralPath $statePath -Recurse -Force -ErrorAction SilentlyContinue
  }
  $rollbackPayload = @'
$ErrorActionPreference = 'Stop'
$programRoot = Join-Path ${env:ProgramFiles} 'Paperboat'
$installed = Join-Path $programRoot 'bin\pb.exe'
$purgeError = $null
function Wait-RollbackProcess($Process, [string]$Operation) {
  if ($null -eq $Process) { throw "$Operation did not return a process handle." }
  if (-not $Process.WaitForExit(1200000)) {
    try { $Process.Kill() } catch { }
    if (-not $Process.WaitForExit(5000)) {
      throw "$Operation exceeded the 20 minute limit and could not be stopped."
    }
    throw "$Operation exceeded the 20 minute limit."
  }
  return [int]$Process.ExitCode
}
try {
  if (Test-Path -LiteralPath $installed -PathType Leaf) {
    $purge = Start-Process -FilePath $installed -ArgumentList @('purge') -PassThru -WindowStyle Hidden
    $purgeExitCode = Wait-RollbackProcess $purge 'Paperboat runtime purge'
    if ($purgeExitCode -ne 0) { throw "Paperboat runtime purge failed with exit code $purgeExitCode." }
  }
} catch {
  $purgeError = $_
}
try {
  # __install --fresh owns this exact root. Remove the payload only after the
  # executable has exited, so the rollback is safe on Windows file locking.
  Remove-Item -LiteralPath $programRoot -Recurse -Force -ErrorAction Stop
  if (Test-Path -LiteralPath $programRoot) {
    throw "Paperboat fresh-install payload remains after rollback."
  }
} catch {
  if ($null -eq $purgeError) { $purgeError = $_ }
}
if ($null -ne $purgeError) { throw $purgeError }
'@
  $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rollbackPayload))
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  try {
    if (Test-Administrator) {
      & $powershell '-NoProfile' '-NonInteractive' '-EncodedCommand' $encodedPayload
      if ($LASTEXITCODE -ne 0) { throw "rollback exited with code $LASTEXITCODE" }
    } elseif (-not (Test-InteractiveUac)) {
      throw 'Paperboat fresh-install rollback requires an elevated administrator PowerShell session when no interactive UAC desktop is available.'
    } else {
      $rollback = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedPayload) -Verb RunAs -PassThru -WindowStyle Hidden
      $rollbackExitCode = Wait-InstallerProcess $rollback 'Paperboat fresh-install rollback'
      if ($rollbackExitCode -ne 0) { throw "rollback exited with code $rollbackExitCode" }
    }
  } catch {
    # Preserve the pair failure as the primary result, but make an incomplete
    # rollback visible so support can safely retry cleanup.
    Write-Warning "Paperboat fresh-install rollback did not complete: $($_.Exception.Message)"
  }
}

if ($freshEnrollment -or -not (Assert-InstalledRelease $installedPb $version $actual)) {
  # __install is implemented by the downloaded pb.exe itself. This is the
  # only binary-install elevation boundary and avoids downloading another
  # executable.
  $arguments = @('__install', '--source', $download, '--version', $version)
  if ($freshEnrollment) { $arguments += '--fresh' }
  $administrator = Test-Administrator
  if (-not $administrator -and -not (Test-InteractiveUac)) {
    throw 'Paperboat installation requires administrator privileges. Run PowerShell as Administrator for unattended or SSH execution, or rerun this command from an interactive desktop to approve the UAC prompt.'
  }
  $installerExecutable = $null
  try { $installerExecutable = Stage-TrustedBootstrap $download } catch { $installerExecutable = $null }
  if ($null -ne $installerExecutable) {
    $arguments[2] = $installerExecutable
  }
  $runAsPath = if ($null -ne $installerExecutable) { $installerExecutable } else { $download }
  if ($administrator) {
    # Keep the elevated path in-process so an administrator SSH session does
    # not depend on an interactive desktop UAC broker. Use the trusted staged
    # copy when available, otherwise retain the verified download path.
    & $runAsPath @arguments
    if ($LASTEXITCODE -ne 0) { throw "Paperboat self-install failed with exit code $LASTEXITCODE." }
  } else {
    $elevatedArguments = @($arguments)
    if ([string]$arguments[2] -match '\s') { $elevatedArguments[2] = '"' + $arguments[2] + '"' }
    try {
      # Do not use Start-Process -Wait here. It waits the entire child tree,
      # including any helper that is intentionally detached by __install.
      $process = Start-Process -FilePath $runAsPath -ArgumentList $elevatedArguments -Verb RunAs -PassThru -WindowStyle Hidden
    } catch {
      throw "Paperboat self-install could not request administrator approval: $($_.Exception.Message)"
    }
    $installExitCode = Wait-InstallerProcess $process 'Paperboat self-install'
    if ($installExitCode -ne 0) { throw "Paperboat self-install failed with exit code $installExitCode." }
  }
}
if (-not (Assert-InstalledRelease $installedPb $version $actual)) { throw "Installed Paperboat does not match verified release $version." }

# The trusted bootstrap is needed only across the elevation boundary. Never
# accumulate verified staging copies after the installed digest is proven.
if ($null -ne $installerExecutable) {
  Remove-Item -LiteralPath $installerExecutable -Force -ErrorAction SilentlyContinue
}

if ($freshEnrollment) {
  # Only cross the replacement boundary after the verified elevated install
  # has succeeded. If UAC is denied or the elevated process cannot start,
  # the existing enrollment remains intact and the token can be retried.
  # __install --fresh already removes machine-wide services and state.
  foreach ($statePath in @(
    (Join-Path $env:LOCALAPPDATA 'Paperboat'),
    (Join-Path $env:APPDATA 'Paperboat')
  )) {
    Remove-Item -LiteralPath $statePath -Recurse -Force -ErrorAction SilentlyContinue
  }
  if ([string]::IsNullOrWhiteSpace($name)) {
    $name = [string]$env:COMPUTERNAME
  }
  $name = $name.Trim().ToLowerInvariant()
  $first = $token.Substring(0, 1)
  $setupMode = if ('02468BDFHJLNPRTVXZ'.Contains($first)) { 'host' } else { 'client' }
  Remove-Item Env:PAPERBOAT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
  # Pair in the original user's process so the CLI profile, DPAPI credentials,
  # endpoint identity, and daemon state belong to the user who pasted the
  # dashboard command. The installed pb elevates only its machine-service
  # commit after this user-owned state has been created.
  & $installedPb pair --server $server --enrollment-token $token --name $name "--setup-mode=$setupMode"
  if ($LASTEXITCODE -ne 0) {
    $pairExitCode = $LASTEXITCODE
    Write-Warning "Paperboat pairing failed with exit code $pairExitCode; rolling back the fresh installation."
    Invoke-FreshPairRollback
    exit $pairExitCode
  }
}
