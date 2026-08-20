[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet('amd64', 'arm64')]
    [string] $Architecture,

    [string] $Channel,

    [Parameter(Mandatory = $true)]
    [string] $StagingDirectory,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [string] $WixCommand = 'wix',

    [string] $ExpectedWixVersion = '5.0.2',

    [switch] $QualificationRollbackHook
)

$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$') {
    throw 'Version must match YYYY.MM.DD.X.'
}
$versionParts = $Version.Split('.')
$year = [int]$versionParts[0]
$month = [int]$versionParts[1]
$day = [int]$versionParts[2]
$revision = [int]$versionParts[3]
if ($month -lt 1 -or $month -gt 12 -or $day -lt 1 -or $day -gt 31 -or $revision -gt 99) {
    throw 'Version must contain a valid month/day and a revision from 0 through 99.'
}
# MSI versions are limited to major.minor.build with major/minor below 256
# and build below 65536. Keep the full release version in release metadata and
# map it deterministically to YY.M.(DD*100+revision) for Windows Installer.
$msiVersion = '{0}.{1}.{2}' -f ($year % 100), $month, (($day * 100) + $revision)
$expectedChannel = if ($Architecture -eq 'amd64') { 'stable' } else { 'beta' }
if ([string]::IsNullOrWhiteSpace($Channel)) {
    $Channel = $expectedChannel
}
if ($Channel -notin @('stable', 'beta')) {
    throw 'Channel must be stable or beta.'
}
if ($Channel -ne $expectedChannel) {
    throw "Architecture $Architecture requires channel $expectedChannel."
}

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$packagingRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory '..'))
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $packagingRoot '..\..'))
$staging = [IO.Path]::GetFullPath($StagingDirectory)
$output = [IO.Path]::GetFullPath($OutputDirectory)

& (Join-Path $scriptDirectory 'validate.ps1')
if ($LASTEXITCODE -ne 0) {
    throw 'Windows packaging contract validation failed.'
}

$requiredFiles = @(
    'pb.exe',
    'pb-launcher.exe',
    'paperboat-runtime.exe',
    'paperboat-hostd.exe',
    'paperboat-updater.exe'
)
foreach ($file in $requiredFiles) {
    $path = Join-Path $staging $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required release-built staging file is missing: $path"
    }
}

$wix = Get-Command $WixCommand -ErrorAction Stop
$wixPath = if (-not [string]::IsNullOrWhiteSpace($wix.Source)) { $wix.Source } else { $wix.Path }
$wixVersionOutput = (& $wixPath --version | Out-String).Trim()
if ($wixVersionOutput -notmatch ("(^|[^0-9]){0}([^0-9]|$)" -f [regex]::Escape($ExpectedWixVersion))) {
    throw "WiX version must be $ExpectedWixVersion, got $wixVersionOutput."
}
$wixPlatform = if ($Architecture -eq 'amd64') { 'x64' } else { 'arm64' }
$source = Join-Path $packagingRoot 'wix\Paperboat.wxs'
$outputPath = Join-Path $output ("paperboat_{0}_windows_{1}.msi" -f $Version, $Architecture)
$rollbackHook = if ($QualificationRollbackHook) { '1' } else { '0' }

New-Item -ItemType Directory -Force -Path $output | Out-Null
$arguments = @(
    'build',
    '-arch', $wixPlatform,
    '-d', "PaperboatVersion=$Version",
    '-d', "PaperboatMSIVersion=$msiVersion",
    '-d', "PaperboatChannel=$Channel",
    '-d', "WixPlatform=$wixPlatform",
    '-d', "StagingDir=$staging",
    '-d', "PackagingRoot=$packagingRoot",
    '-d', "QualificationRollbackHook=$rollbackHook",
    '-ext', 'WixToolset.Util.wixext'
)
$arguments += @('-o', $outputPath, $source)

& $wixPath @arguments
if ($LASTEXITCODE -ne 0) {
    throw "WiX failed with exit code $LASTEXITCODE."
}
if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
    throw "WiX reported success but did not produce $outputPath."
}

Write-Output "Built unsigned Windows $Architecture MSI: $outputPath"
Write-Output 'Windows MSI integrity is provided by TUF metadata, checksums, PE architecture validation, and provenance. Authenticode and RFC 3161 timestamping are optional enhancements.'
