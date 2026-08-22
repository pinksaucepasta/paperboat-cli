[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('amd64', 'arm64')]
    [string] $Architecture,

    [Parameter(Mandatory = $true)]
    [string] $StagingDirectory,

    [Parameter(Mandatory = $true)]
    [string] $MsiPath,

    [Parameter(Mandatory = $true)]
    [string] $ZipPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'signing-common.ps1')

$staging = [IO.Path]::GetFullPath($StagingDirectory)
$msi = [IO.Path]::GetFullPath($MsiPath)
$zip = [IO.Path]::GetFullPath($ZipPath)
$channel = 'stable'
$msiPlatform = if ($Architecture -eq 'amd64') { 'x64' } else { 'Arm64' }

$requiredPayloads = @(
    'pb.exe',
    'pb-launcher.exe',
    'paperboat-runtime.exe',
    'paperboat-hostd.exe',
    'paperboat-updater.exe'
)
foreach ($name in $requiredPayloads) {
    $path = Join-Path $staging $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Cross-architecture payload is missing: $path"
    }
    if ((Get-PeMachine -FilePath $path) -ne $Architecture) {
        throw "Cross-architecture payload has the wrong PE machine: $name"
    }
}

if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
    throw "Cross-architecture MSI is missing: $msi"
}
$installer = New-Object -ComObject WindowsInstaller.Installer
$summary = $installer.SummaryInformation($msi, 0)
$template = [string]$summary.Property(7)
if ($template -notmatch ('^{0}(;|$)' -f [regex]::Escape($msiPlatform))) {
    throw "MSI template '$template' does not target $msiPlatform."
}

if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {
    throw "Cross-architecture ZIP is missing: $zip"
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("paperboat-cross-artifact-{0}" -f ([guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $temporary)
    $entries = @(Get-ChildItem -LiteralPath $temporary -File | ForEach-Object Name)
    $expectedEntries = @('paperboat-windows.json', 'pb-launcher.exe', 'pb.exe')
    $entryDifference = @(Compare-Object -ReferenceObject $expectedEntries -DifferenceObject $entries)
    if ($entries.Count -ne $expectedEntries.Count -or $entryDifference.Count -ne 0) {
        throw "Portable ZIP entries are incorrect: $([string]::Join(', ', $entries))"
    }
    foreach ($name in @('pb.exe', 'pb-launcher.exe')) {
        if ((Get-PeMachine -FilePath (Join-Path $temporary $name)) -ne $Architecture) {
            throw "Portable ZIP payload has the wrong PE machine: $name"
        }
    }
    $metadata = Get-Content -LiteralPath (Join-Path $temporary 'paperboat-windows.json') -Raw | ConvertFrom-Json
    if ($metadata.platform -ne 'windows' -or $metadata.architecture -ne $Architecture -or $metadata.channel -ne $channel -or $metadata.stability -ne $channel) {
        throw 'Portable ZIP release metadata does not match its Windows target.'
    }
    if ($metadata.native_e2e -ne 'required_before_stable_release') {
        throw 'Portable ZIP does not preserve the native-hardware stable release gate.'
    }
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

[ordered]@{
    schema = 'paperboat.windows-cross-artifact-verification/v1'
    architecture = $Architecture
    channel = $channel
    pe_payloads = $requiredPayloads.Count
    msi_template = $template
    zip_entries = 3
    native_execution = $false
} | ConvertTo-Json -Compress
