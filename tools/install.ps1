<# Paperboat one-shot native Windows bootstrap endpoint. #>
$ErrorActionPreference = 'Stop'
$server = 'https://api.pprbt.dev'
$token = $env:PAPERBOAT_ENROLLMENT_TOKEN
$first = $token.Substring(0,1)
$second = $token.Substring(1,1)
$role = if ('02468BDFHJLNPRTVXZ'.Contains($first)) { 'host' } else { 'client' }
$name = $env:PAPERBOAT_MACHINE_NAME
if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($token)) { throw 'Paperboat enrollment command is missing its one-time credential.' }
if ($role -notin @('host','client')) { throw 'Paperboat enrollment role must be host or client.' }
$setupMode = $role
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
$repo = if ($env:PAPERBOAT_GITHUB_REPOSITORY) { $env:PAPERBOAT_GITHUB_REPOSITORY } else { 'pinksaucepasta/paperboat-cli' }
$current = (Invoke-WebRequest -UseBasicParsing "$server/current.json").Content | ConvertFrom-Json
$version = $current.version
if ([string]::IsNullOrWhiteSpace($version)) { throw 'Paperboat release metadata did not contain a version.' }
$releaseBase = "https://github.com/$repo/releases/download/$version"
$asset = "pb-windows-$arch.exe"
$dir = Join-Path $env:LOCALAPPDATA 'Paperboat\bootstrap'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir ("pb-$version-$arch.exe")
$sums = Join-Path $dir 'SHA256SUMS'
function Download-ReleaseFile([string]$url, [string]$output) {
  $temporary = "$output.download"
  Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
  $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
  if ($null -ne $curl) {
    & $curl.Source '--silent' '--show-error' '-L' '--fail' '--retry' '4' '--retry-all-errors' '--connect-timeout' '20' '--output' $temporary $url
    if ($LASTEXITCODE -eq 0) { Move-Item -LiteralPath $temporary -Destination $output -Force; return }
    throw "Download failed: $url (curl exit $LASTEXITCODE)."
  }
  Invoke-WebRequest -UseBasicParsing $url -OutFile $temporary
  Move-Item -LiteralPath $temporary -Destination $output -Force
}
Download-ReleaseFile "$releaseBase/SHA256SUMS" $sums
$expected = ((Get-Content -Raw $sums) -split "`r?`n" | Where-Object { $_ -match "\s\*?$([regex]::Escape($asset))$" } | ForEach-Object { ($_ -split '\s+')[0] } | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($expected)) { throw "Release checksum for $asset is missing." }
$existingHash = if (Test-Path -LiteralPath $exe -PathType Leaf) { (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant() } else { '' }
if ($existingHash -ne $expected.ToLowerInvariant()) { Download-ReleaseFile "$releaseBase/$asset" $exe }
$actual = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
if ($actual -ne $expected.ToLowerInvariant()) { throw "Release checksum verification failed for $asset." }
& $exe pair --server $server --enrollment-token $token --name $name "--setup-mode=$setupMode"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
