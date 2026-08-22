<# Paperboat one-shot native Windows bootstrap endpoint. #>
$ErrorActionPreference = 'Stop'

$server = 'https://api.pprbt.dev'
$token = [string]$env:PAPERBOAT_ENROLLMENT_TOKEN
$name = [string]$env:PAPERBOAT_MACHINE_NAME
if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($token)) { throw 'Paperboat enrollment command is missing its one-time credential.' }
if ($token -notmatch '^[0-9A-Z]{26}$') { throw 'Paperboat enrollment command has an invalid one-time credential.' }

$first = $token.Substring(0, 1)
$role = if ('02468BDFHJLNPRTVXZ'.Contains($first)) { 'host' } else { 'client' }
if ($role -notin @('host', 'client')) { throw 'Paperboat enrollment role must be host or client.' }
$setupMode = $role
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
$repo = if ($env:PAPERBOAT_GITHUB_REPOSITORY) { [string]$env:PAPERBOAT_GITHUB_REPOSITORY } else { 'pinksaucepasta/paperboat-cli' }
if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Paperboat release repository is invalid.' }

$current = (Invoke-WebRequest -UseBasicParsing -Uri "$server/current.json" -TimeoutSec 30).Content | ConvertFrom-Json
$version = [string]$current.version
if ($current.schema -ne 'paperboat.release-current/v1' -or $version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') { throw 'Paperboat release metadata is invalid.' }

$releaseBase = "https://github.com/$repo/releases/download/$version"
$asset = "paperboat_${version}_windows_${arch}.msi"
$dir = Join-Path $env:LOCALAPPDATA 'Paperboat\bootstrap'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$msi = Join-Path $dir $asset
$sums = Join-Path $dir "SHA256SUMS-$version"
$log = Join-Path $dir "msiexec-$version-$arch.log"
$installedPb = Join-Path ${env:ProgramFiles} 'Paperboat\bin\pb.exe'
$msiexec = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'msiexec.exe'

function Get-ReleaseChecksum([string]$Path, [string]$Asset) {
  foreach ($line in Get-Content -LiteralPath $Path) {
    if ($line -notmatch '^(?<hash>[0-9A-Fa-f]{64})[ \t]+\*?(?<name>(?:\./)?[^ \t]+)$') { continue }
    $name = $Matches.name
    if ([string]::Equals($name, $Asset, [System.StringComparison]::Ordinal) -or [string]::Equals($name, "./$Asset", [System.StringComparison]::Ordinal)) {
      return $Matches.hash.ToLowerInvariant()
    }
  }
  return ''
}

function Download-ReleaseFile([string]$Url, [string]$Output) {
  $temporary = "$Output.download"
  for ($attempt = 1; $attempt -le 4; $attempt++) {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    try {
      $curl = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue
      if ($null -ne $curl) {
        & $curl.Source '--silent' '--show-error' '--location' '--fail' '--retry' '1' '--retry-all-errors' '--connect-timeout' '20' '--max-time' '300' '--output' $temporary $Url
        if ($LASTEXITCODE -ne 0) { throw "curl exit $LASTEXITCODE" }
      } else {
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $temporary -TimeoutSec 300 -MaximumRedirection 5
      }
      Move-Item -LiteralPath $temporary -Destination $Output -Force
      return
    } catch {
      Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
      if ($attempt -eq 4) { throw "Download failed for $Url after $attempt attempts: $($_.Exception.Message)" }
      Start-Sleep -Seconds ($attempt * 2)
    }
  }
}

function Assert-InstalledVersion([string]$Path, [string]$ExpectedVersion) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  $output = (& $Path --version 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { return $false }
  return $output -match ("(?m)^.*\bVersion\s+" + [regex]::Escape($ExpectedVersion) + "\s*$")
}

function Install-ReleaseMsi([string]$Path, [string]$LogPath) {
  if (-not (Test-Path -LiteralPath $msiexec -PathType Leaf)) { throw "Trusted Windows Installer executable is unavailable: $msiexec" }
  $arguments = @('/i', ('"{0}"' -f $Path), '/qn', '/norestart', '/L*v', ('"{0}"' -f $LogPath))
  # The MSI is per-machine. Elevate only the trusted Windows Installer process,
  # keeping the one-time enrollment token in this unelevated process and out of
  # the child command line/environment entirely.
  $process = Start-Process -FilePath $msiexec -ArgumentList $arguments -Verb RunAs -PassThru -WindowStyle Hidden
  if (-not $process.WaitForExit(1200000)) {
    try { $process.Kill() } finally { $process.WaitForExit() }
    throw 'Windows Installer exceeded the 20 minute installation limit.'
  }
  if ($process.ExitCode -notin @(0, 3010)) { throw "Windows Installer failed with exit code $($process.ExitCode). See $LogPath." }
}

Download-ReleaseFile "$releaseBase/SHA256SUMS" $sums
$expected = Get-ReleaseChecksum $sums $asset
if ([string]::IsNullOrWhiteSpace($expected)) { throw "Release checksum for $asset is missing." }
$existingHash = if (Test-Path -LiteralPath $msi -PathType Leaf) { (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant() } else { '' }
if ($existingHash -ne $expected) { Download-ReleaseFile "$releaseBase/$asset" $msi }
$actual = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "Release checksum verification failed for $asset." }

if (-not (Assert-InstalledVersion $installedPb $version)) { Install-ReleaseMsi $msi $log }
if (-not (Assert-InstalledVersion $installedPb $version)) { throw "Installed Paperboat launcher does not report exact release version $version." }

Remove-Item Env:PAPERBOAT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
& $installedPb pair --server $server --enrollment-token $token --name $name "--setup-mode=$setupMode"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
