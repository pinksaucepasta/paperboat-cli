[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$')]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$')]
    [string] $UpgradeVersion,

    [Parameter(Mandatory = $true)]
    [ValidateSet('amd64', 'arm64')]
    [string] $Architecture,

    [Parameter(Mandatory = $true)]
    [string] $WixCommand,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$stageRoot = Join-Path $outputRoot 'stage'
$msiRoot = Join-Path $outputRoot 'msi'
$channel = 'stable'
New-Item -ItemType Directory -Force -Path $stageRoot, $msiRoot | Out-Null

$nativeArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$expectedArchitecture = if ($Architecture -eq 'amd64') { 'X64' } else { 'Arm64' }
if ($nativeArchitecture -ne $expectedArchitecture) {
    throw "Native qualification artifact build requested $Architecture on $nativeArchitecture."
}

$wixVersion = (& $WixCommand --version | Out-String).Trim()
if ($wixVersion -notmatch '(^|[^0-9])5\.0\.2([^0-9]|$)') {
    throw "WiX 5.0.2 is required for qualification artifacts, got $wixVersion."
}

function Invoke-GoBuild {
    param(
        [Parameter(Mandatory = $true)][string] $Output,
        [Parameter(Mandatory = $true)][string] $Package,
        [string] $LdFlags = ''
    )
    $arguments = @('build', '-buildvcs=false', '-trimpath')
    if ($LdFlags -ne '') {
        $arguments += @('-ldflags', $LdFlags)
    }
    $arguments += @('-o', $Output, $Package)
    & go @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed for $Package with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "go build reported success without producing $Output."
    }
}

function Build-Payload {
    param(
        [Parameter(Mandatory = $true)][string] $PayloadVersion,
        [Parameter(Mandatory = $true)][string] $PayloadDirectory
    )
    New-Item -ItemType Directory -Force -Path $PayloadDirectory | Out-Null
    $commit = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { 'native-qualification' }
    $ldflags = "-s -w -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=$PayloadVersion -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Commit=$commit -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=1"
    $cli = Join-Path $PayloadDirectory 'pb.exe'
    $launcher = Join-Path $PayloadDirectory 'pb-launcher.exe'
    Invoke-GoBuild -Output $cli -Package './cmd/pb' -LdFlags $ldflags
    Invoke-GoBuild -Output $launcher -Package './cmd/pb-launcher' -LdFlags $ldflags
    foreach ($role in @('paperboat-runtime.exe', 'paperboat-hostd.exe', 'paperboat-updater.exe')) {
        Copy-Item -LiteralPath $cli -Destination (Join-Path $PayloadDirectory $role)
    }
}

function Assert-NativePE {
    param([Parameter(Mandatory = $true)][string] $Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "$Path is not an MZ executable."
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 26 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "$Path has no valid PE signature."
    }
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $optionalMagic = [BitConverter]::ToUInt16($bytes, $peOffset + 24)
    $expectedMachine = if ($Architecture -eq 'amd64') { 0x8664 } else { 0xaa64 }
    if ($machine -ne $expectedMachine -or $optionalMagic -ne 0x20b) {
        throw ("$Path has machine 0x{0:x4} and optional header 0x{1:x4}." -f $machine, $optionalMagic)
    }
}

Push-Location $repositoryRoot
try {
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = if ($Architecture -eq 'amd64') { 'amd64' } else { 'arm64' }
    Build-Payload -PayloadVersion $Version -PayloadDirectory (Join-Path $stageRoot 'fresh')
    Build-Payload -PayloadVersion $UpgradeVersion -PayloadDirectory (Join-Path $stageRoot 'upgrade')
    & (Join-Path $PSScriptRoot 'build-msi.ps1') `
        -Version $Version `
        -Architecture $Architecture `
        -Channel $channel `
        -StagingDirectory (Join-Path $stageRoot 'fresh') `
        -OutputDirectory $msiRoot `
        -WixCommand $WixCommand `
        -ExpectedWixVersion '5.0.2' `
        -QualificationRollbackHook
    if ($LASTEXITCODE -ne 0) { throw 'Fresh qualification MSI build failed.' }
    & (Join-Path $PSScriptRoot 'build-msi.ps1') `
        -Version $UpgradeVersion `
        -Architecture $Architecture `
        -Channel $channel `
        -StagingDirectory (Join-Path $stageRoot 'upgrade') `
        -OutputDirectory $msiRoot `
        -WixCommand $WixCommand `
        -ExpectedWixVersion '5.0.2' `
        -QualificationRollbackHook
    if ($LASTEXITCODE -ne 0) { throw 'Upgrade qualification MSI build failed.' }
    $fixture = Join-Path $outputRoot 'paperboat-windows-service-fixture.exe'
    Invoke-GoBuild -Output $fixture -Package './packaging/windows/e2e/service-fixture'
    foreach ($payload in @(
        (Join-Path $stageRoot 'fresh\pb.exe'),
        (Join-Path $stageRoot 'fresh\pb-launcher.exe'),
        (Join-Path $stageRoot 'fresh\paperboat-runtime.exe'),
        (Join-Path $stageRoot 'fresh\paperboat-hostd.exe'),
        (Join-Path $stageRoot 'fresh\paperboat-updater.exe'),
        (Join-Path $stageRoot 'upgrade\pb.exe'),
        (Join-Path $stageRoot 'upgrade\pb-launcher.exe'),
        (Join-Path $stageRoot 'upgrade\paperboat-runtime.exe'),
        (Join-Path $stageRoot 'upgrade\paperboat-hostd.exe'),
        (Join-Path $stageRoot 'upgrade\paperboat-updater.exe'),
        $fixture
    )) {
        Assert-NativePE -Path $payload
    }
}
finally {
    Pop-Location
}

$freshMsi = Join-Path $msiRoot ("paperboat_{0}_windows_{1}.msi" -f $Version, $Architecture)
$upgradeMsi = Join-Path $msiRoot ("paperboat_{0}_windows_{1}.msi" -f $UpgradeVersion, $Architecture)
foreach ($path in @($freshMsi, $upgradeMsi)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Qualification MSI was not produced: $path"
    }
}
$manifest = [ordered]@{
    schema = 'paperboat.windows-native-qualification-inputs/v1'
    architecture = $Architecture
    stability = 'stable'
    version = $Version
    upgrade_version = $UpgradeVersion
    fresh_msi = $freshMsi
    upgrade_msi = $upgradeMsi
    service_fixture = (Join-Path $outputRoot 'paperboat-windows-service-fixture.exe')
    wix_version = '5.0.2'
    authenticode_status = 'not_present'
    signing_required_for_release = $false
    integrity_authority = 'tuf_sha256_pe_architecture_sbom_provenance'
}
$manifestPath = Join-Path $outputRoot 'native-qualification-inputs.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

if ($env:GITHUB_ENV) {
    @(
        "PAPERBOAT_WINDOWS_E2E_MSI=$freshMsi",
        "PAPERBOAT_WINDOWS_E2E_UPGRADE_MSI=$upgradeMsi",
        "PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE=$(Join-Path $outputRoot 'paperboat-windows-service-fixture.exe')",
        "PAPERBOAT_WINDOWS_E2E_OUTPUT=$outputRoot"
    ) | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
}
Write-Output ($manifest | ConvertTo-Json -Depth 8)
