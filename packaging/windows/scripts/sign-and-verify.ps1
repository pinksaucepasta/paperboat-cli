[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Path,

    [Parameter(Mandatory = $true)]
    [ValidateSet('amd64', 'arm64')]
    [string] $Architecture,

    [string] $ExpectedPublisher = $env:PAPERBOAT_WINDOWS_PUBLISHER_SUBJECT,

    [string] $TimestampUrl = $env:PAPERBOAT_WINDOWS_TIMESTAMP_URL,

    [string] $PfxBase64EnvironmentVariable = 'PAPERBOAT_WINDOWS_SIGNING_PFX_B64',

    [string] $PfxPasswordEnvironmentVariable = 'PAPERBOAT_WINDOWS_SIGNING_PFX_PASSWORD',

    [string] $Description = 'Paperboat native Windows release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'signing-common.ps1')

if ([string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
    $ExpectedPublisher = 'Paperboat optional signing certificate'
}

$signToolPath = $null
$pfxValue = [Environment]::GetEnvironmentVariable($PfxBase64EnvironmentVariable, 'Process')
$passwordValue = [Environment]::GetEnvironmentVariable($PfxPasswordEnvironmentVariable, 'Process')
if ([string]::IsNullOrWhiteSpace($pfxValue)) {
    Write-Warning 'No Authenticode certificate configured; continuing with TUF/checksum integrity.'
    exit 0
}
if ([string]::IsNullOrWhiteSpace($passwordValue)) {
    Write-Warning 'No Authenticode certificate password configured; continuing with TUF/checksum integrity.'
    exit 0
}

$signToolPath = Resolve-SignTool

$pfxPath = Join-Path ([IO.Path]::GetTempPath()) ("paperboat-signing-{0}.pfx" -f ([guid]::NewGuid().ToString('N')))
$secureSecret = $null
$importedCertificates = @()
$existingThumbprints = @(
    Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
        ForEach-Object { ([string]$_.Thumbprint).ToUpperInvariant() }
)

try {
    try {
        $pfxBytes = [Convert]::FromBase64String($pfxValue)
    }
    catch {
        throw 'The protected signing PFX secret is not valid base64.'
    }
    if ($pfxBytes.Length -lt 128) {
        throw 'The protected signing PFX secret is unexpectedly small.'
    }
    [IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

    $secureSecret = ConvertTo-SecureString -String $passwordValue -AsPlainText -Force
    $importedCertificates = @(
        Import-PfxCertificate `
            -FilePath $pfxPath `
            -Password $secureSecret `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Exportable:$false
    )
    $certificate = $importedCertificates |
        Where-Object {
            $_.HasPrivateKey -and
            $_.Subject -eq $ExpectedPublisher -and
            @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value }) -contains '1.3.6.1.5.5.7.3.3'
        } |
        Select-Object -First 1
    if ($null -eq $certificate) {
        throw 'The protected PFX does not contain a matching code-signing certificate.'
    }
    $thumbprint = ([string]$certificate.Thumbprint).ToUpperInvariant()

    foreach ($file in $Path) {
        $resolved = [IO.Path]::GetFullPath($file)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "Signing input is missing: $resolved"
        }
        $extension = [IO.Path]::GetExtension($resolved).ToLowerInvariant()
        if ($extension -notin @('.exe', '.msi')) {
            throw "Only PE .exe and MSI files may be signed: $resolved"
        }
        if ($extension -eq '.exe' -and (Get-PeMachine -FilePath $resolved) -ne $Architecture) {
            throw "PE architecture mismatch for $([IO.Path]::GetFileName($resolved))."
        }

        $signArguments = @(
            'sign',
            '/sha1', $thumbprint,
            '/fd', 'SHA256',
            '/tr', $TimestampUrl,
            '/td', 'SHA256',
            '/d', $Description,
            $resolved
        )
        & $signToolPath @signArguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "signtool signing failed for $([IO.Path]::GetFileName($resolved))."
        }

        $null = Get-AuthenticodeEvidence -FilePath $resolved -ExpectedPublisher $ExpectedPublisher -SignToolPath $signToolPath
        Write-Output ("Signed and verified {0}" -f [IO.Path]::GetFileName($resolved))
    }
}
finally {
    if ($null -ne $secureSecret) {
        $secureSecret.Dispose()
    }
    $pfxValue = $null
    $passwordValue = $null
    $pfxBytes = $null
    if (Test-Path -LiteralPath $pfxPath -PathType Leaf) {
        Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
    }
    foreach ($certificate in $importedCertificates) {
        $thumbprint = ([string]$certificate.Thumbprint).ToUpperInvariant()
        if ($existingThumbprints -notcontains $thumbprint) {
            Remove-Item -LiteralPath ("Cert:\CurrentUser\My\{0}" -f $thumbprint) -Force -ErrorAction SilentlyContinue
        }
    }
}
