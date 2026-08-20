[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet('amd64', 'arm64')]
    [string] $Architecture,

    [Parameter(Mandatory = $true)]
    [ValidateSet('stable', 'beta')]
    [string] $Channel,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [AllowEmptyString()]
    [string] $ExpectedPublisher = $env:PAPERBOAT_WINDOWS_PUBLISHER_SUBJECT,

    [AllowEmptyString()]
    [string] $TimestampUrl = $env:PAPERBOAT_WINDOWS_TIMESTAMP_URL,

    [Parameter(Mandatory = $true)]
    [string] $WixVersion = '5.0.2'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'signing-common.ps1')

$expectedChannel = if ($Architecture -eq 'amd64') { 'stable' } else { 'beta' }
if ($Channel -ne $expectedChannel) {
    throw "Architecture $Architecture requires channel $expectedChannel."
}

$output = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $output -PathType Container)) {
    throw "Windows release output directory is missing: $output"
}
$signToolPath = $null

$expectedPeNames = @(
    "paperboat_${Version}_windows_${Architecture}_pb.exe",
    "paperboat_${Version}_windows_${Architecture}_pb-launcher.exe",
    "paperboat_${Version}_windows_${Architecture}_paperboat-runtime.exe",
    "paperboat_${Version}_windows_${Architecture}_paperboat-hostd.exe",
    "paperboat_${Version}_windows_${Architecture}_paperboat-updater.exe"
)
$peFiles = @()
foreach ($name in $expectedPeNames) {
    $path = Join-Path $output $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Expected signed Windows PE is missing: $name"
    }
    if ((Get-PeMachine -FilePath $path) -ne $Architecture) {
        throw "Windows PE architecture mismatch: $name"
    }
    $evidence = Get-AuthenticodeEvidence -FilePath $path -ExpectedPublisher $ExpectedPublisher -SignToolPath $signToolPath
    $peFiles += [ordered]@{
        path = $name
        kind = 'pe'
        architecture = $Architecture
        channel = $Channel
        pe_machine = $Architecture
        sha256 = Get-Sha256 -FilePath $path
        size = ([IO.FileInfo]$path).Length
        authenticode_status = $evidence.authenticode_status
        publisher_subject = $evidence.publisher_subject
        signer_thumbprint = $evidence.signer_thumbprint
        timestamped = $evidence.timestamped
        timestamp_subject = $evidence.timestamp_subject
    }
}

$msiName = "paperboat_${Version}_windows_${Architecture}.msi"
$msiPath = Join-Path $output $msiName
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw "Signed Windows MSI is missing: $msiName"
}
$msiEvidence = Get-AuthenticodeEvidence -FilePath $msiPath -ExpectedPublisher $ExpectedPublisher -SignToolPath $signToolPath
$msiFile = [ordered]@{
    path = $msiName
    kind = 'msi'
    architecture = $Architecture
    channel = $Channel
    sha256 = Get-Sha256 -FilePath $msiPath
    size = ([IO.FileInfo]$msiPath).Length
    authenticode_status = $msiEvidence.authenticode_status
    publisher_subject = $msiEvidence.publisher_subject
    signer_thumbprint = $msiEvidence.signer_thumbprint
    timestamped = $msiEvidence.timestamped
    timestamp_subject = $msiEvidence.timestamp_subject
}

$zipName = "paperboat_${Version}_windows_${Architecture}.zip"
$zipPath = Join-Path $output $zipName
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
    throw "Signed Windows ZIP is missing: $zipName"
}

$zipTemporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("paperboat-zip-verify-{0}" -f ([guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Force -Path $zipTemporaryDirectory | Out-Null
$zipContents = @()
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notin @('pb.exe', 'pb-launcher.exe', 'paperboat-windows.json')) {
                throw "Portable ZIP contains an unexpected entry: $($entry.FullName)"
            }
            if ($entry.FullName -in @('pb.exe', 'pb-launcher.exe')) {
                $entryPath = Join-Path $zipTemporaryDirectory $entry.FullName
                $input = $entry.Open()
                $outputStream = [IO.File]::Open($entryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $input.CopyTo($outputStream)
                }
                finally {
                    $outputStream.Dispose()
                    $input.Dispose()
                }
                if ((Get-PeMachine -FilePath $entryPath) -ne $Architecture) {
                    throw "Portable ZIP PE architecture mismatch: $($entry.FullName)"
                }
                $entryEvidence = Get-AuthenticodeEvidence -FilePath $entryPath -ExpectedPublisher $ExpectedPublisher -SignToolPath $signToolPath
                $zipContents += [ordered]@{
                    path = $entry.FullName
                    architecture = $Architecture
                    pe_machine = $Architecture
                    authenticode_status = $entryEvidence.authenticode_status
                    publisher_subject = $entryEvidence.publisher_subject
                    signer_thumbprint = $entryEvidence.signer_thumbprint
                    timestamped = $entryEvidence.timestamped
                    timestamp_subject = $entryEvidence.timestamp_subject
                }
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}
finally {
    if (Test-Path -LiteralPath $zipTemporaryDirectory -PathType Container) {
        Remove-Item -LiteralPath $zipTemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if (@($zipContents).Count -ne 2) {
    throw 'Portable ZIP must contain exactly two signed executable entries.'
}
$zipFile = [ordered]@{
    path = $zipName
    kind = 'archive'
    architecture = $Architecture
    channel = $Channel
    sha256 = Get-Sha256 -FilePath $zipPath
    size = ([IO.FileInfo]$zipPath).Length
    authenticode_status = 'not_applicable'
    contents_authenticode_status = if (@($zipContents | Where-Object { $_.authenticode_status -ne 'valid' }).Count -eq 0) { 'valid' } else { 'not_required' }
    contents = $zipContents
        publisher_subject = $ExpectedPublisher
        timestamped = (@($zipContents | Where-Object { $_.timestamped -ne $true }).Count -eq 0)
    timestamp_scope = 'contained_pe_files'
}

$artifacts = @($peFiles + @($msiFile) + @($zipFile))
$manifest = [ordered]@{
    schema = 'paperboat.windows-signing/v1'
    product = 'paperboat'
    release = $Version
    platform = 'windows'
    architecture = $Architecture
    channel = $Channel
    runner = $env:RUNNER_NAME
    runner_os = $env:ImageOS
    windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    wix_version = $WixVersion
    publisher_subject = $ExpectedPublisher
    timestamp_url = $TimestampUrl
    checksums_refreshed = $true
    artifacts = $artifacts
}
$manifestPath = Join-Path $output "windows-signing-manifest-${Architecture}.json"
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$checksumPath = Join-Path $output "windows-checksums-${Architecture}.sha256"
$checksumLines = $artifacts |
    Sort-Object -Property path |
    ForEach-Object { "{0} *{1}" -f $_.sha256, $_.path }
$checksumLines | Set-Content -LiteralPath $checksumPath -Encoding ascii

$spdxFiles = $artifacts | ForEach-Object {
    [ordered]@{
        SPDXID = "SPDXRef-File-$($_.path -replace '[^A-Za-z0-9.-]', '-')"
        fileName = $_.path
        checksums = @([ordered]@{ algorithm = 'SHA256'; checksumValue = $_.sha256 })
        licenseConcluded = 'NOASSERTION'
        copyrightText = 'NOASSERTION'
    }
}
$spdx = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = "paperboat-windows-$Architecture-$Version"
    documentNamespace = "https://github.com/pinksaucepasta/paperboat/spdx/windows/$Version/$Architecture"
    creationInfo = [ordered]@{
        created = (Get-Date).ToUniversalTime().ToString('o')
        creators = @('Tool: Paperboat Windows release pipeline')
    }
    files = @($spdxFiles)
}
$spdxPath = Join-Path $output "windows-sbom-${Architecture}.spdx.json"
$spdx | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $spdxPath -Encoding utf8

$provenance = [ordered]@{
    schema = 'paperboat.windows-provenance/v1'
    product = 'paperboat'
    release = $Version
    commit = $env:GITHUB_SHA
    repository = $env:GITHUB_REPOSITORY
    platform = 'windows'
    architecture = $Architecture
    channel = $Channel
    runner = $env:RUNNER_NAME
    runner_os = $env:ImageOS
    windows_build = $manifest.windows_build
    wix_version = $WixVersion
    signing = [ordered]@{
        publisher_subject = $ExpectedPublisher
        timestamp_url = $TimestampUrl
        pfx_secret_name = ''
        password_secret_name = ''
        private_material_persisted = $false
    }
    artifacts = $artifacts | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; kind = $_.kind } }
}
$provenancePath = Join-Path $output "windows-provenance-${Architecture}.json"
$provenance | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $provenancePath -Encoding utf8

Write-Output ("Generated Windows signing, checksum, SBOM, and provenance handoff for {0}." -f $Architecture)
