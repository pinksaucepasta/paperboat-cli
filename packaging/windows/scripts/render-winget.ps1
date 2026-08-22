[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [string] $Repository,

    [Parameter(Mandatory = $true)]
    [string] $Amd64Msi,

    [Parameter(Mandatory = $true)]
    [string] $Arm64Msi,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [AllowEmptyString()]
    [string] $ExpectedPublisher = $env:PAPERBOAT_WINDOWS_PUBLISHER_SUBJECT
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$packagingRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory '..'))
$templateRoot = Join-Path $packagingRoot 'winget'
$output = [IO.Path]::GetFullPath($OutputDirectory)

foreach ($path in @($Amd64Msi, $Arm64Msi)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Final signed MSI is missing: $path"
    }
}

function Get-MsiProperty {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $PropertyName
    )

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Path, 0)
    $view = $database.OpenView("SELECT Value FROM Property WHERE Property='$PropertyName'")
    [void]$view.Execute()
    $record = $view.Fetch()
    if ($null -eq $record) {
        throw "MSI property $PropertyName is missing from $([IO.Path]::GetFileName($Path))."
    }
    $value = ([string]$record.StringData(1)).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "MSI property $PropertyName is empty in $([IO.Path]::GetFileName($Path))."
    }
    return $value
}

$amd64MsiPath = [IO.Path]::GetFullPath($Amd64Msi)
$arm64MsiPath = [IO.Path]::GetFullPath($Arm64Msi)
$amd64Hash = ([string](Get-FileHash -LiteralPath $amd64MsiPath -Algorithm SHA256).Hash).ToLowerInvariant()
$arm64Hash = ([string](Get-FileHash -LiteralPath $arm64MsiPath -Algorithm SHA256).Hash).ToLowerInvariant()
$amd64ProductCode = Get-MsiProperty -Path $amd64MsiPath -PropertyName 'ProductCode'
$arm64ProductCode = Get-MsiProperty -Path $arm64MsiPath -PropertyName 'ProductCode'
$releaseNotesUrl = "https://github.com/$Repository/releases/tag/$Version"
$releaseBaseUrl = "https://github.com/$Repository/releases/download/$Version"

$replacements = @{
    '{{VERSION}}' = $Version
    '{{RELEASE_NOTES_URL}}' = $releaseNotesUrl
    '{{WINDOWS_AMD64_MSI_URL}}' = "$releaseBaseUrl/paperboat_${Version}_windows_amd64.msi"
    '{{WINDOWS_AMD64_MSI_SHA256}}' = $amd64Hash
    '{{WINDOWS_AMD64_MSI_PRODUCT_CODE}}' = $amd64ProductCode
    '{{WINDOWS_ARM64_MSI_URL}}' = "$releaseBaseUrl/paperboat_${Version}_windows_arm64.msi"
    '{{WINDOWS_ARM64_MSI_SHA256}}' = $arm64Hash
    '{{WINDOWS_ARM64_MSI_PRODUCT_CODE}}' = $arm64ProductCode
}

Remove-Item -LiteralPath $output -Recurse -Force -ErrorAction SilentlyContinue
$destinationDirectory = Join-Path $output 'stable'
New-Item -ItemType Directory -Force -Path $destinationDirectory | Out-Null
foreach ($template in Get-ChildItem -LiteralPath (Join-Path $templateRoot 'stable') -Filter '*.yaml' -File | Sort-Object Name) {
    $content = Get-Content -LiteralPath $template.FullName -Raw
    foreach ($replacement in $replacements.GetEnumerator()) {
        $content = $content.Replace($replacement.Key, $replacement.Value)
    }
    $manifestContent = ($content -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    if ($manifestContent -match '\{\{[^}]+\}\}') {
        throw "Unrendered WinGet placeholder remains in $($template.Name)."
    }
    $manifestContent | Set-Content -LiteralPath (Join-Path $destinationDirectory $template.Name) -Encoding utf8
}

Write-Output ("Rendered final-hash WinGet manifests in {0}." -f $output)
