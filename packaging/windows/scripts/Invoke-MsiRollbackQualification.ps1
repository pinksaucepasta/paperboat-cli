[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MsiPath,
    [Parameter(Mandatory = $true)][string] $ServiceFixturePath,
    [Parameter(Mandatory = $true)][string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$serviceName = 'PaperboatHostd'
$installRoot = Join-Path ${env:ProgramFiles} 'Paperboat'
$registryPath = 'HKLM:\Software\Paperboat'
$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$resolvedMsi = [IO.Path]::GetFullPath($MsiPath)
$resolvedFixture = [IO.Path]::GetFullPath($ServiceFixturePath)
$logPath = Join-Path $OutputDirectory 'rollback-injected-failure.log'
$reportPath = Join-Path $OutputDirectory 'rollback-qualification.json'

function Assert-Qualification([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "qualification_assertion_failed: $Message" }
}

function Get-PaperboatProducts {
    @(Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object {
        $item = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($null -ne $item -and $item.DisplayName -eq 'Paperboat') { $item }
    })
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
Assert-Qualification (Test-Path $resolvedMsi -PathType Leaf) "MSI is missing: $resolvedMsi"
Assert-Qualification (Test-Path $resolvedFixture -PathType Leaf) "Service fixture is missing: $resolvedFixture"
Assert-Qualification (-not (Test-Path $installRoot)) 'Paperboat install root already exists.'
Assert-Qualification (-not (Test-Path $registryPath)) 'Paperboat registry already exists.'
Assert-Qualification (@(Get-PaperboatProducts).Count -eq 0) 'Paperboat product is already registered.'
Assert-Qualification ($null -eq (Get-Service $serviceName -ErrorAction SilentlyContinue)) "$serviceName already exists."

$fixtureCommand = "`"$resolvedFixture`" $serviceName"
New-Service -Name $serviceName -BinaryPathName $fixtureCommand -DisplayName 'Administrator-owned rollback fixture' -StartupType Manual | Out-Null
$fixtureBefore = Get-CimInstance Win32_Service | Where-Object Name -eq $serviceName

try {
    $arguments = "/i `"$resolvedMsi`" /qn /norestart /L*v `"$logPath`""
    $process = Start-Process $msiexec -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    Assert-Qualification ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) "MSI unexpectedly succeeded despite the administrator-owned service collision; exit=$($process.ExitCode)."

    $fixtureAfter = Get-CimInstance Win32_Service | Where-Object Name -eq $serviceName
    Assert-Qualification ($null -ne $fixtureAfter) 'MSI rollback removed the administrator-owned service fixture.'
    Assert-Qualification ($fixtureAfter.PathName -eq $fixtureBefore.PathName) 'MSI rollback changed the administrator-owned service fixture.'
    Assert-Qualification ($null -eq (Get-Service PaperboatUpdated -ErrorAction SilentlyContinue)) 'PaperboatUpdated remains after failed-install rollback.'
    Assert-Qualification (-not (Test-Path $installRoot)) 'Program Files payload remains after failed-install rollback.'
    Assert-Qualification (-not (Test-Path $registryPath)) 'Product registry remains after failed-install rollback.'
    Assert-Qualification (@(Get-PaperboatProducts).Count -eq 0) 'ARP product remains after failed-install rollback.'

    $serviceConflictExitCode = $process.ExitCode
}
finally {
    if ($null -ne (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
        & sc.exe delete $serviceName | Out-Null
    }
}

$deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
while ($null -ne (Get-Service $serviceName -ErrorAction SilentlyContinue) -and [DateTimeOffset]::UtcNow -lt $deadline) {
    Start-Sleep -Milliseconds 100
}
Assert-Qualification ($null -eq (Get-Service $serviceName -ErrorAction SilentlyContinue)) 'Service collision fixture cleanup failed.'

$rollbackLogPath = Join-Path $OutputDirectory 'rollback-after-product-writes.log'
$rollbackArguments = "/i `"$resolvedMsi`" PAPERBOAT_QUALIFY_ROLLBACK=1 /qn /norestart /L*v `"$rollbackLogPath`""
$rollbackProcess = Start-Process $msiexec -ArgumentList $rollbackArguments -Wait -PassThru -WindowStyle Hidden
Assert-Qualification ($rollbackProcess.ExitCode -ne 0 -and $rollbackProcess.ExitCode -ne 3010) "Qualification rollback hook unexpectedly succeeded; exit=$($rollbackProcess.ExitCode)."
Assert-Qualification (Select-String -LiteralPath $rollbackLogPath -SimpleMatch 'Paperboat qualification injected a transactional rollback' -Quiet) 'MSI log does not prove the qualification rollback hook executed.'
Assert-Qualification ($null -eq (Get-Service PaperboatHostd -ErrorAction SilentlyContinue)) 'PaperboatHostd remains after transactional rollback.'
Assert-Qualification ($null -eq (Get-Service PaperboatUpdated -ErrorAction SilentlyContinue)) 'PaperboatUpdated remains after transactional rollback.'
Assert-Qualification (-not (Test-Path $installRoot)) 'Program Files payload remains after transactional rollback.'
Assert-Qualification (-not (Test-Path $registryPath)) 'Product registry remains after transactional rollback.'
Assert-Qualification (@(Get-PaperboatProducts).Count -eq 0) 'ARP product remains after transactional rollback.'

[ordered]@{
    schema = 'paperboat.windows-msi-rollback-qualification/v1'
    status = 'passed'
    architecture = 'amd64'
    native_tested = $true
    windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    service_conflict_exit_code = $serviceConflictExitCode
    service_conflict_failed_closed = $true
    administrator_service_preserved = $true
    injected_failure = 'qualification_only_after_files_and_registry_before_services'
    rollback_exit_code = $rollbackProcess.ExitCode
    rollback_clean = $true
    verified_at = [DateTimeOffset]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 6 | Set-Content $reportPath -Encoding UTF8
