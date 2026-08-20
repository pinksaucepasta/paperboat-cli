[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MsiPath,
    [Parameter(Mandatory = $true)][string] $Version,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [ValidateSet('prepare', 'verify')][string] $Phase = 'prepare'
)

$ErrorActionPreference = 'Stop'
$taskName = 'PaperboatInterruptedMsiQualification'
$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$installRoot = Join-Path ${env:ProgramFiles} 'Paperboat'
$registryPath = 'HKLM:\Software\Paperboat'
$statePath = Join-Path $OutputDirectory 'interrupted-msi-state.json'
$reportPath = Join-Path $OutputDirectory 'interrupted-msi-qualification.json'
$logPath = Join-Path $OutputDirectory 'interrupted-msi.log'
$resolvedMsi = [IO.Path]::GetFullPath($MsiPath)
$scriptPath = [IO.Path]::GetFullPath($PSCommandPath)

function Assert-Qualification([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "qualification_assertion_failed: $Message" }
}

function Get-PaperboatProducts {
    @(Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object {
        $item = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($null -ne $item -and $item.DisplayName -eq 'Paperboat') { $item }
    })
}

function Get-PaperboatSshdPath {
    $service = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object Name -eq 'PaperboatSshd' | Select-Object -First 1
    if ($null -eq $service) { return $null }
    return [string]$service.PathName
}

function Write-Json([string] $Path, [object] $Value) {
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

if ($Phase -eq 'prepare') {
    Assert-Qualification (Test-Path $resolvedMsi -PathType Leaf) "MSI is missing: $resolvedMsi"
    Assert-Qualification (-not (Test-Path $installRoot)) 'Paperboat install root already exists.'
    Assert-Qualification (-not (Test-Path $registryPath)) 'Paperboat product registry already exists.'
    Assert-Qualification (@(Get-PaperboatProducts).Count -eq 0) 'Paperboat is already registered with Windows Installer.'

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-Qualification ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Administrator rights are required.'

    $baselineSshd = Get-PaperboatSshdPath
    $verifyArguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -MsiPath `"$resolvedMsi`" -Version `"$Version`" -OutputDirectory `"$OutputDirectory`" -Phase verify"
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $verifyArguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principalSpec = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principalSpec -Force | Out-Null

    Write-Json $statePath ([ordered]@{
        schema = 'paperboat.windows-interrupted-msi-state/v1'
        phase = 'armed'
        msi = $resolvedMsi
        version = $Version
        baseline_paperboat_sshd_path = $baselineSshd
        armed_at = [DateTimeOffset]::UtcNow.ToString('o')
    })

    $arguments = "/i `"$resolvedMsi`" /qn /norestart /L*v `"$logPath`""
    $process = Start-Process $msiexec -ArgumentList $arguments -PassThru -WindowStyle Hidden
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    $observedProductState = $false
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ((Test-Path $registryPath) -or (Test-Path (Join-Path $installRoot 'bin\pb.exe'))) {
            $observedProductState = $true
            break
        }
        if ($process.HasExited) { break }
        Start-Sleep -Milliseconds 10
    }
    $process.Refresh()
    Assert-Qualification $observedProductState 'Windows Installer never created observable product state before the deadline.'
    Assert-Qualification (-not $process.HasExited) 'Windows Installer completed before an in-progress interruption could be triggered.'

    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    $state.phase = 'reboot_triggered_during_install'
    $state | Add-Member -NotePropertyName msiexec_pid -NotePropertyValue $process.Id
    $state | Add-Member -NotePropertyName product_state_observed -NotePropertyValue $true
    $state | Add-Member -NotePropertyName process_active_at_trigger -NotePropertyValue $true
    $state | Add-Member -NotePropertyName reboot_triggered_at -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o'))
    Write-Json $statePath $state
    & shutdown.exe /r /t 0 /f
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$deadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
while ([DateTimeOffset]::UtcNow -lt $deadline -and @(Get-Process msiexec -ErrorAction SilentlyContinue).Count -gt 0) {
    Start-Sleep -Seconds 1
}

$files = @('pb.exe', 'pb-launcher.exe', 'paperboat-runtime.exe', 'paperboat-hostd.exe', 'paperboat-updater.exe')
$presentFiles = @($files | Where-Object { Test-Path (Join-Path $installRoot "bin\$_") })
$services = @(Get-Service PaperboatHostd, PaperboatUpdated -ErrorAction SilentlyContinue)
$products = @(Get-PaperboatProducts)
$registryPresent = Test-Path $registryPath
$installedCoherently = $presentFiles.Count -eq $files.Count -and $services.Count -eq 2 -and $products.Count -eq 1 -and $registryPresent
$rolledBackCleanly = $presentFiles.Count -eq 0 -and $services.Count -eq 0 -and $products.Count -eq 0 -and -not $registryPresent -and -not (Test-Path $installRoot)
Assert-Qualification ($installedCoherently -or $rolledBackCleanly) "Recovery left partial state: files=$($presentFiles.Count), services=$($services.Count), products=$($products.Count), registry=$registryPresent, root=$(Test-Path $installRoot)."

$outcome = if ($installedCoherently) { 'completed_coherently' } else { 'rolled_back_cleanly' }
if ($installedCoherently) {
    $productCode = $products[0].PSChildName
    $cleanup = Start-Process $msiexec -ArgumentList "/x $productCode /qn /norestart /L*v `"$(Join-Path $OutputDirectory 'interrupted-msi-cleanup.log')`"" -Wait -PassThru -WindowStyle Hidden
    Assert-Qualification ($cleanup.ExitCode -eq 0 -or $cleanup.ExitCode -eq 3010) "Cleanup uninstall failed with exit code $($cleanup.ExitCode)."
}

Assert-Qualification (-not (Test-Path $installRoot)) 'Install root remains after recovery cleanup.'
Assert-Qualification (-not (Test-Path $registryPath)) 'Product registry remains after recovery cleanup.'
Assert-Qualification (@(Get-PaperboatProducts).Count -eq 0) 'ARP product remains after recovery cleanup.'
Assert-Qualification ((Get-PaperboatSshdPath) -eq $state.baseline_paperboat_sshd_path) 'Pre-existing PaperboatSshd changed during interrupted installation recovery.'

Write-Json $reportPath ([ordered]@{
    schema = 'paperboat.windows-interrupted-msi-qualification/v1'
    status = 'passed'
    architecture = 'amd64'
    native_tested = $true
    windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    version = $Version
    interruption = 'forced_reboot_after_product_state_while_msiexec_active'
    recovery_outcome = $outcome
    cleanup = 'passed'
    paperboat_sshd_preserved = $true
    verified_at = [DateTimeOffset]::UtcNow.ToString('o')
})
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
