Set-StrictMode -Version Latest

function Resolve-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Path
    }

    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
        throw 'signtool.exe was not found on PATH and Program Files (x86) is unavailable.'
    }

    $kitsRoot = Join-Path $programFilesX86 'Windows Kits\10\bin'
    $candidate = Get-ChildItem -LiteralPath $kitsRoot -Filter 'signtool.exe' -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object -Property FullName -Descending |
        Select-Object -First 1
    if ($null -eq $candidate) {
        throw 'signtool.exe was not found on PATH or under the Windows 10 SDK.'
    }
    return $candidate.FullName
}

function Get-PeMachine {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath
    )

    $bytes = [IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "Not a PE file: $FilePath"
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length) {
        throw "PE header is outside the file: $FilePath"
    }
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "PE signature is invalid: $FilePath"
    }

    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    switch ($machine) {
        0x8664 { return 'amd64' }
        0xAA64 { return 'arm64' }
        default { throw "Unsupported PE machine 0x{0:X4}: {1}" -f $machine, $FilePath }
    }
}

function Invoke-SignToolVerify {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SignToolPath,

        [Parameter(Mandatory = $true)]
        [string] $FilePath
    )

    $null = @(& $SignToolPath verify /pa /all /tw $FilePath 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "signtool verification failed for $([IO.Path]::GetFileName($FilePath))."
    }
}

function Get-AuthenticodeEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath,

        [AllowEmptyString()]
        [string] $ExpectedPublisher,

        [AllowEmptyString()]
        [string] $SignToolPath
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $FilePath
    if ([string]$signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        return [ordered]@{
            authenticode_status = 'not_present'
            publisher_subject = ''
            signer_thumbprint = ''
            timestamped = $false
            timestamp_subject = ''
        }
    }
    $subject = [string]$signature.SignerCertificate.Subject
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublisher) -and $subject -ne $ExpectedPublisher) {
        throw "Authenticode publisher mismatch for $([IO.Path]::GetFileName($FilePath))."
    }

    $timestampProperty = $signature.PSObject.Properties['TimeStamperCertificate']
    $timestamped = $null -ne $timestampProperty -and $null -ne $timestampProperty.Value
    if ($timestamped -and -not [string]::IsNullOrWhiteSpace($SignToolPath)) {
        Invoke-SignToolVerify -SignToolPath $SignToolPath -FilePath $FilePath
    }

    [ordered]@{
        authenticode_status = 'valid'
        publisher_subject = $subject
        signer_thumbprint = ([string]$signature.SignerCertificate.Thumbprint).ToUpperInvariant()
        timestamped = $timestamped
        timestamp_subject = if ($timestamped) { [string]$timestampProperty.Value.Subject } else { '' }
    }
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath
    )

    return ([string](Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash).ToLowerInvariant()
}
