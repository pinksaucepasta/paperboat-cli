[CmdletBinding()]
param(
    [string] $CacheDirectory = (Join-Path $HOME '.paperboat-ci\winget-v1.29.280')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$bundleUrl = 'https://github.com/microsoft/winget-cli/releases/download/v1.29.280/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
$bundleHash = '0809fa9f52e395d6e7de692331dce847ac991952675116bb4d8aae2ddcc20946'
$dependenciesUrl = 'https://github.com/microsoft/winget-cli/releases/download/v1.29.280/DesktopAppInstaller_Dependencies.zip'
$dependenciesHash = '3bbfcaa5cb011c48fac48d896d64a5c7c6898859a9f3d01555c8cd000f4e2962'

function Get-PinnedAsset {
    param(
        [Parameter(Mandatory = $true)] [string] $Url,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedHash
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $cachedHash = ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToLowerInvariant()
        if ($cachedHash -ne $ExpectedHash) {
            Remove-Item -LiteralPath $Path -Force
        }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $download = "$Path.download"
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $Url -OutFile $download
        $downloadHash = ([string](Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash).ToLowerInvariant()
        if ($downloadHash -ne $ExpectedHash) {
            Remove-Item -LiteralPath $download -Force
            throw "Pinned WinGet asset hash mismatch for $Url."
        }
        Move-Item -LiteralPath $download -Destination $Path
    }
    $actualHash = ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToLowerInvariant()
    if ($actualHash -ne $ExpectedHash) {
        throw "Cached WinGet asset hash mismatch for $Path."
    }
}

New-Item -ItemType Directory -Force -Path $CacheDirectory | Out-Null
$bundle = Join-Path $CacheDirectory 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
$dependenciesArchive = Join-Path $CacheDirectory 'DesktopAppInstaller_Dependencies.zip'
Get-PinnedAsset -Url $bundleUrl -Path $bundle -ExpectedHash $bundleHash
Get-PinnedAsset -Url $dependenciesUrl -Path $dependenciesArchive -ExpectedHash $dependenciesHash

$temporaryRoot = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP }
$dependencyRoot = Join-Path $temporaryRoot 'paperboat-winget-dependencies-v1.29.280'
Remove-Item -LiteralPath $dependencyRoot -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath $dependenciesArchive -DestinationPath $dependencyRoot
$dependencies = @(Get-ChildItem -LiteralPath (Join-Path $dependencyRoot 'x64') -Filter '*.appx' -File | Sort-Object Name)
if ($dependencies.Count -ne 3) {
    throw "Expected exactly three x64 WinGet dependencies, found $($dependencies.Count)."
}

Add-AppxPackage -Path $bundle -DependencyPath @($dependencies.FullName) -ForceApplicationShutdown
$package = Get-AppxPackage -Name Microsoft.DesktopAppInstaller |
    Sort-Object Version -Descending |
    Select-Object -First 1
if ($null -eq $package) {
    throw 'Microsoft.DesktopAppInstaller was not registered after installing the pinned bundle.'
}
$winget = Join-Path $package.InstallLocation 'winget.exe'
if (-not (Test-Path -LiteralPath $winget -PathType Leaf)) {
    throw "Pinned winget executable is missing: $winget"
}
$actualVersion = (& $winget --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $actualVersion -ne 'v1.29.280') {
    throw "Expected pinned winget v1.29.280, got '$actualVersion'."
}
if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    $package.InstallLocation | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
}
Write-Output "Pinned WinGet validator ready: $actualVersion at $winget"
