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

if ($metadataUrl -notmatch '^https://') { throw 'Paperboat release metadata URL must use HTTPS.' }
if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Paperboat release repository is invalid.' }
if ($freshEnrollment -and $token -notmatch '^[0-9A-Z]{26}$') { throw 'Paperboat enrollment token is invalid.' }

$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
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
# Clear the download's Zone.Identifier before the first execution. Windows
# PowerShell can otherwise reject the version probe itself with Access denied.
Unblock-File -LiteralPath $download -ErrorAction SilentlyContinue

# Hardened Windows policies can deny execution from a user-writable temporary
# directory even after it has been verified and unblocked. An already-elevated
# session stages the same verified bytes in the administrator-owned Paperboat
# bootstrap directory before invoking the self-installer.
$trustedBootstrapDirectory = Join-Path ${env:ProgramFiles} 'Paperboat\bootstrap'
function Stage-TrustedBootstrap([string]$Source) {
  New-Item -ItemType Directory -Force -Path $trustedBootstrapDirectory | Out-Null
  # Never replace a fixed bootstrap path: an older Paperboat process may still
  # have it open, and Windows correctly rejects that replacement with access
  # denied. Each verified download gets its own immutable staging path.
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

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $false }
  # IsInRole can report the Administrators group for a split UAC token even
  # when the current process cannot write machine-wide paths. Probe the exact
  # directory used for trusted staging so we never surface a raw Access Denied
  # before the RunAs fallback gets a chance to handle it.
  $probe = Join-Path $trustedBootstrapDirectory ('.elevation-' + [guid]::NewGuid().ToString('N'))
  try {
    New-Item -ItemType Directory -Force -Path $trustedBootstrapDirectory | Out-Null
    New-Item -ItemType File -Path $probe -Force | Out-Null
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    return $true
  } catch {
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    return $false
  }
}

if ($freshEnrollment -or -not (Assert-InstalledVersion $installedPb $version) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $installedPb -ErrorAction SilentlyContinue).Hash.ToLowerInvariant() -ne $actual) {
  # __install is implemented by the downloaded pb.exe itself. This is the
  # only elevation boundary and avoids downloading another executable.
  $arguments = @('__install', '--source', $download, '--version', $version)
  if ($freshEnrollment) { $arguments += '--fresh' }
  # An already-elevated SSH or deployment session has no interactive desktop
  # on which Windows can show another UAC prompt. Invoke directly in that
  # case; ordinary desktop terminals still use RunAs and show the normal UAC
  # prompt.
  if (Test-Administrator) {
    $installerExecutable = $null
    try { $installerExecutable = Stage-TrustedBootstrap $download } catch { $installerExecutable = $null }
    # Always launch through ShellExecute's RunAs verb. The bootstrap process
    # performs its own administrator check, and direct invocation from an SSH
    # session can retain a filtered token even when this shell can write the
    # staging directory.
    if ($null -ne $installerExecutable) {
      # The elevated child must read the verified source through a path it can
      # access. User TEMP ACLs can deny a full administrator token, while the
      # staged Program Files copy is already trusted and readable.
      $arguments[2] = $installerExecutable
    }
    $runAsPath = if ($null -ne $installerExecutable) { $installerExecutable } else { $download }
    try {
      $process = Start-Process -FilePath $runAsPath -ArgumentList $arguments -Verb RunAs -PassThru -Wait -WindowStyle Hidden
    } catch {
      if ($runAsPath -ne $download) {
        try {
          $process = Start-Process -FilePath $download -ArgumentList $arguments -Verb RunAs -PassThru -Wait -WindowStyle Hidden
        } catch {
          throw "Paperboat self-install could not start with administrator privileges: $($_.Exception.Message)"
        }
      } else {
        throw "Paperboat self-install could not start with administrator privileges: $($_.Exception.Message)"
      }
    }
    if ($process.ExitCode -ne 0) { throw "Paperboat self-install failed with exit code $($process.ExitCode)." }
  } else {
    $process = Start-Process -FilePath $download -ArgumentList $arguments -Verb RunAs -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(1200000)) {
      try { $process.Kill() } finally { $process.WaitForExit() }
      throw 'Paperboat installation exceeded the 20 minute limit.'
    }
    if ($process.ExitCode -ne 0) { throw "Paperboat self-install failed with exit code $($process.ExitCode)." }
  }
}
if (-not (Assert-InstalledVersion $installedPb $version)) { throw "Installed Paperboat does not report release $version." }

if ($freshEnrollment) {
  # Only cross the replacement boundary after the verified elevated install
  # has succeeded. If UAC is denied or the elevated session cannot start,
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
  $pairArguments = @('pair', '--server', $server, '--enrollment-token', $token, '--name', $name, "--setup-mode=$setupMode")
  if (Test-Administrator) {
    # The pair command installs the managed runtime after CLI enrollment. Run
    # it with the same full token as __install so its Windows elevation bridge
    # can register services from an OpenSSH session without Access Denied.
    $pairProcess = Start-Process -FilePath $installedPb -ArgumentList $pairArguments -Verb RunAs -PassThru -Wait
    if ($pairProcess.ExitCode -ne 0) { exit $pairProcess.ExitCode }
  } else {
    & $installedPb @pairArguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  }
}
