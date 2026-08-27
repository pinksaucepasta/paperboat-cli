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

$dir = Join-Path $env:TEMP 'Paperboat\bootstrap'
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

function Assert-InstalledVersion([string]$Path, [string]$ExpectedVersion) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  $output = (& $Path --version 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { return $false }
  return $output -match ("(?m)^.*\bVersion\s+" + [regex]::Escape($ExpectedVersion) + "\s*$")
}

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($freshEnrollment -or -not (Assert-InstalledVersion $installedPb $version) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $installedPb -ErrorAction SilentlyContinue).Hash.ToLowerInvariant() -ne $actual) {
  # __install is implemented by the downloaded pb.exe itself. This is the
  # only elevation boundary and avoids downloading another executable.
  $arguments = @('__install', '--source', $download, '--version', $version)
  if ($freshEnrollment) { $arguments += '--fresh' }
  # An already-elevated SSH or deployment session has no interactive desktop
  # on which Windows can show another UAC prompt. Starting it with RunAs in
  # that environment returns Access is denied even though the caller already
  # has a full administrator token. Execute directly in that case; ordinary
  # desktop terminals still use RunAs and show the normal UAC prompt.
  if (Test-Administrator) {
    $process = Start-Process -FilePath $download -ArgumentList $arguments -PassThru -WindowStyle Hidden
  } else {
    $process = Start-Process -FilePath $download -ArgumentList $arguments -Verb RunAs -PassThru -WindowStyle Hidden
  }
  if (-not $process.WaitForExit(1200000)) {
    try { $process.Kill() } finally { $process.WaitForExit() }
    throw 'Paperboat installation exceeded the 20 minute limit.'
  }
  if ($process.ExitCode -ne 0) { throw "Paperboat self-install failed with exit code $($process.ExitCode)." }
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
  $first = $token.Substring(0, 1)
  $setupMode = if ('02468BDFHJLNPRTVXZ'.Contains($first)) { 'host' } else { 'client' }
  Remove-Item Env:PAPERBOAT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
  & $installedPb pair --server $server --enrollment-token $token --name $name "--setup-mode=$setupMode"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
