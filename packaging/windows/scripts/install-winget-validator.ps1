[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$moduleVersion = [version]'1.9.25190'
$module = Get-Module -ListAvailable -Name Microsoft.WinGet.Client |
    Where-Object Version -EQ $moduleVersion |
    Select-Object -First 1
if ($null -eq $module) {
    Install-Module -Name Microsoft.WinGet.Client -RequiredVersion $moduleVersion -Repository PSGallery -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.WinGet.Client -RequiredVersion $moduleVersion -Force

# A repository-scoped Actions token cannot read microsoft/winget-cli and makes
# the module's exact-version lookup return a misleading 404.
Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
Repair-WinGetPackageManager -Version '1.29.280' -Force

$windowsApps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
$env:PATH = "$windowsApps;$env:PATH"
$winget = Get-Command winget.exe -ErrorAction Stop
$actualVersion = (& $winget.Path --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $actualVersion -ne 'v1.29.280') {
    throw "Expected pinned winget v1.29.280, got '$actualVersion'."
}
if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    $windowsApps | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
}
Write-Output "Pinned WinGet validator ready: $actualVersion at $($winget.Path)"
