[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $MsiPath,

    [Parameter(Mandatory = $true)]
    [string] $UpgradeMsiPath,

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
    [string] $ServiceFixturePath,

    [string] $NativeTestExecutable = '',

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:events = @()
$script:installedByHarness = $false
$script:upgradeInstalled = $false
$script:dynamicPreviewServiceName = $null
$script:preexistingPaperboatSshd = $null
$script:msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$script:installRoot = Join-Path ${env:ProgramFiles} 'Paperboat'
$script:binaryRoot = Join-Path $script:installRoot 'bin'
$script:stateRoot = Join-Path ${env:ProgramData} 'Paperboat'
$script:registryPath = 'HKLM:\Software\Paperboat'

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$resolvedOutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$resolvedMsiPath = [IO.Path]::GetFullPath($MsiPath)
$resolvedUpgradeMsiPath = [IO.Path]::GetFullPath($UpgradeMsiPath)
$resolvedFixturePath = [IO.Path]::GetFullPath($ServiceFixturePath)
$reportPath = Join-Path $resolvedOutputDirectory 'native-windows-qualification.json'

function Add-QualificationEvent {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][ValidateSet('started', 'passed', 'failed', 'blocked')][string] $Status,
        [string] $Detail = ''
    )
    $script:events += [ordered]@{
        name = $Name
        status = $Status
        detail = $Detail
    }
}

function Assert-Qualification {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) {
        throw "qualification_assertion_failed: $Message"
    }
}

function ConvertTo-NormalizedMachinePathEntry {
    param([AllowEmptyString()][string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Value.Trim().Trim('"'))
    try {
        return [IO.Path]::GetFullPath($expanded).TrimEnd('\')
    }
    catch {
        return $expanded.TrimEnd('\')
    }
}

function Get-MachinePathEntries {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        $false
    )
    Assert-Qualification ($null -ne $key) 'The machine environment registry key is unavailable.'
    try {
        $rawPath = [string]$key.GetValue(
            'Path',
            '',
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
    finally {
        $key.Dispose()
    }
    return @($rawPath.Split(';') | ForEach-Object { ConvertTo-NormalizedMachinePathEntry $_ })
}

function Quote-WindowsArgument {
    param([Parameter(Mandatory = $true)][string] $Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-Msi {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $LogPath,
        [Parameter(Mandatory = $true)][string] $Operation
    )
    $logArgument = Quote-WindowsArgument $LogPath
    $argumentLine = (($Arguments + @('/qn', '/norestart', '/L*v', $logArgument)) -join ' ')
    Add-QualificationEvent -Name "msiexec_$Operation" -Status 'started' -Detail $argumentLine
    $process = Start-Process -FilePath $script:msiexec -ArgumentList $argumentLine -Wait -PassThru -WindowStyle Hidden
    Assert-Qualification ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) "msiexec $Operation returned exit code $($process.ExitCode). See $LogPath."
    Add-QualificationEvent -Name "msiexec_$Operation" -Status 'passed' -Detail "exit_code=$($process.ExitCode); log=$LogPath"
}

function Get-PaperboatServices {
    @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -in @('PaperboatHostd', 'PaperboatUpdated')
    })
}

function Get-PaperboatPreviewServices {
    @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like 'PaperboatPreview-*'
    })
}

function Get-InstalledPaperboatProducts {
    $entries = @()
    foreach ($root in @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )) {
        if (Test-Path -LiteralPath $root) {
            $entries += @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                $item = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if ($null -ne $item -and $item.DisplayName -eq 'Paperboat') {
                    $item
                }
            })
        }
    }
    return @($entries)
}

function Assert-Preflight {
    Assert-Qualification (Test-Path -LiteralPath $script:msiexec -PathType Leaf) "msiexec.exe is unavailable at $($script:msiexec)."
    Assert-Qualification (Test-Path -LiteralPath $resolvedMsiPath -PathType Leaf) "Fresh MSI is missing: $resolvedMsiPath"
    Assert-Qualification (Test-Path -LiteralPath $resolvedUpgradeMsiPath -PathType Leaf) "Upgrade MSI is missing: $resolvedUpgradeMsiPath"
    Assert-Qualification (Test-Path -LiteralPath $resolvedFixturePath -PathType Leaf) "Windows service fixture is missing: $resolvedFixturePath"
    Assert-Qualification ([IO.Path]::GetExtension($resolvedFixturePath) -ieq '.exe') "Windows service fixture must be an .exe."
    Assert-Qualification ([Environment]::Is64BitOperatingSystem) 'Qualification requires a 64-bit Windows operating system.'
    $nativeArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $expectedArchitecture = if ($Architecture -eq 'amd64') { 'X64' } else { 'Arm64' }
    Assert-Qualification ($nativeArchitecture -eq $expectedArchitecture) "Requested $Architecture qualification on native architecture $nativeArchitecture."
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-Qualification ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Qualification must run with administrator rights.'
    Assert-Qualification (@(Get-PaperboatServices).Count -eq 0) 'PaperboatHostd or PaperboatUpdated already exists; refusing to overwrite an unmanaged test state.'
    Assert-Qualification (@(Get-PaperboatPreviewServices).Count -eq 0) 'A PaperboatPreview-* service already exists; refusing to overwrite an unmanaged test state.'
    Assert-Qualification (-not (Test-Path -LiteralPath $script:registryPath)) 'HKLM:\Software\Paperboat already exists; refusing to overwrite an unmanaged test state.'
    Assert-Qualification (-not (Test-Path -LiteralPath $script:installRoot)) "$($script:installRoot) already exists; refusing to overwrite an unmanaged test state."
    $script:preexistingPaperboatSshd = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'PaperboatSshd' } | Select-Object -First 1)
    Add-QualificationEvent -Name 'preflight' -Status 'passed' -Detail "native_architecture=$nativeArchitecture; requested_architecture=$Architecture"
}

function Stage-MsiPathFixtures {
    $fixtureRoot = Join-Path $resolvedOutputDirectory 'installer path with spaces 漢字'
    $longPathsEnabled = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -ErrorAction Stop).LongPathsEnabled
    while ((Join-Path $fixtureRoot 'paperboat fresh install.msi').Length -lt 200) {
        $fixtureRoot = Join-Path $fixtureRoot 'supported-long-path-segment'
    }
    New-Item -ItemType Directory -Force -Path $fixtureRoot | Out-Null
    $freshFixture = Join-Path $fixtureRoot 'paperboat fresh install.msi'
    $upgradeFixture = Join-Path $fixtureRoot 'paperboat upgrade install.msi'
    Copy-Item -LiteralPath $resolvedMsiPath -Destination $freshFixture -Force
    Copy-Item -LiteralPath $resolvedUpgradeMsiPath -Destination $upgradeFixture -Force
    Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $freshFixture).Hash -eq (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedMsiPath).Hash) 'Fresh MSI path fixture hash differs from its source.'
    Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $upgradeFixture).Hash -eq (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedUpgradeMsiPath).Hash) 'Upgrade MSI path fixture hash differs from its source.'
    $script:qualifiedFreshMsiPath = $freshFixture
    $script:qualifiedUpgradeMsiPath = $upgradeFixture
    Add-QualificationEvent -Name 'msi_path_fixtures' -Status 'passed' -Detail "spaces_and_unicode=true; long_paths_enabled=$longPathsEnabled; fresh_path_length=$($freshFixture.Length); root=$fixtureRoot"
}

function Assert-InstalledPayload {
    param([Parameter(Mandatory = $true)][string] $ExpectedVersion)
    Assert-Qualification (Test-Path -LiteralPath $script:registryPath) 'Paperboat machine registry state is missing after MSI install.'
    $registry = Get-ItemProperty -LiteralPath $script:registryPath
    Assert-Qualification ($registry.ReleaseVersion -eq $ExpectedVersion) "ReleaseVersion=$($registry.ReleaseVersion), expected $ExpectedVersion."
    $expectedWixPlatform = if ($Architecture -eq 'amd64') { 'x64' } else { 'arm64' }
    Assert-Qualification ($registry.Architecture -eq $expectedWixPlatform) "Architecture=$($registry.Architecture), expected $expectedWixPlatform."
    Assert-Qualification ($registry.Channel -eq $(if ($Architecture -eq 'amd64') { 'stable' } else { 'beta' })) 'Installed channel is incorrect.'

    foreach ($file in @('pb.exe', 'pb-launcher.exe', 'paperboat-runtime.exe', 'paperboat-hostd.exe', 'paperboat-updater.exe')) {
        $path = Join-Path $script:binaryRoot $file
        Assert-Qualification (Test-Path -LiteralPath $path -PathType Leaf) "Installed payload is missing $path."
    }
    $machinePathEntries = @(Get-MachinePathEntries)
    $expectedPathEntry = ConvertTo-NormalizedMachinePathEntry $script:binaryRoot
    $paperboatPathEntryCount = @($machinePathEntries | Where-Object { $_ -ieq $expectedPathEntry }).Count
    Assert-Qualification ($paperboatPathEntryCount -eq 1) "The MSI registered $paperboatPathEntryCount Paperboat bin entries in the machine PATH; expected exactly one normalized entry for $expectedPathEntry."
    foreach ($directory in @(
        (Join-Path $script:stateRoot 'ssh'),
        (Join-Path $script:stateRoot 'updates\current'),
        (Join-Path $script:stateRoot 'updates\rollback'),
        (Join-Path $script:stateRoot 'logs')
    )) {
        Assert-Qualification (Test-Path -LiteralPath $directory -PathType Container) "Installed state directory is missing $directory."
    }
    Assert-Qualification (Test-Path -LiteralPath (Join-Path $script:stateRoot 'ssh\provisioning-hook.json') -PathType Leaf) 'OpenSSH provisioning hook is missing.'

    $services = Get-PaperboatServices
    Assert-Qualification ($services.Count -eq 2) "Expected exactly two Paperboat SCM services, found $($services.Count)."
    foreach ($service in $services) {
        $expectedBinary = if ($service.Name -eq 'PaperboatHostd') { 'paperboat-hostd.exe' } else { 'paperboat-updater.exe' }
        $expectedArgument = if ($service.Name -eq 'PaperboatHostd') { '__runtime-hostd' } else { '__runtime-updated' }
        Assert-Qualification ($service.StartMode -eq 'Manual') "$($service.Name) StartMode=$($service.StartMode), expected Manual from the MSI demand-start contract."
        Assert-Qualification ($service.StartName -ieq 'LocalSystem') "$($service.Name) StartName=$($service.StartName), expected LocalSystem."
        Assert-Qualification ($service.PathName -match [regex]::Escape((Join-Path $script:binaryRoot $expectedBinary))) "$($service.Name) does not point at its installed binary: $($service.PathName)"
        Assert-Qualification ($service.PathName -match [regex]::Escape($expectedArgument)) "$($service.Name) is missing its fixed runtime argument: $($service.PathName)"
    }
    Add-QualificationEvent -Name 'msi_payload_assertions' -Status 'passed' -Detail "version=$ExpectedVersion; services=PaperboatHostd,PaperboatUpdated"
}

function New-OwnedPreviewCleanupFixture {
    $name = 'PaperboatPreview-0123456789abcdef'
    $definitionRoot = Join-Path $script:stateRoot 'services'
    $definitionPath = Join-Path $definitionRoot ($name + '.json')
    $previewStateRoot = Join-Path $script:stateRoot 'previews\msi-cleanup-fixture'
    $descriptorPath = Join-Path $previewStateRoot 'descriptor.json'
    New-Item -ItemType Directory -Force -Path $definitionRoot, $previewStateRoot | Out-Null
    $arguments = @(
        '__runtime-preview',
        '--state-root', $previewStateRoot,
        '--name', 'msi-cleanup-fixture',
        '--descriptor', $descriptorPath,
        '--service-definition', $definitionPath
    )
    $definition = [ordered]@{
        schema = 'paperboat.windows-service/v1'
        name = $name
        display_name = $name
        description = 'Paperboat MSI cleanup qualification fixture'
        executable = (Join-Path $script:binaryRoot 'pb.exe')
        arguments = $arguments
        environment = @{ PAPERBOAT_RUNTIME_SERVICE_SCOPE = 'system' }
        account = 'SYSTEM'
    }
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($definitionPath, ($definition | ConvertTo-Json -Depth 10), $utf8NoBom)
    $commandLine = (Quote-WindowsArgument $definition.executable) + ' ' + (($arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    New-Service `
        -Name $name `
        -BinaryPathName $commandLine `
        -DisplayName 'Paperboat cleanup fixture' `
        -Description 'Paperboat MSI cleanup qualification fixture' `
        -StartupType Manual `
        -ErrorAction Stop | Out-Null
    $script:dynamicPreviewServiceName = $name
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    Assert-Qualification ($null -ne $service) "Owned preview cleanup fixture $name was not registered with SCM."
    Add-QualificationEvent -Name 'dynamic_preview_cleanup_fixture' -Status 'passed' -Detail "service=$name; state=stopped; definition=$definitionPath"
}

function Assert-OwnedPreviewCleanupFixturePresent {
    if ([string]::IsNullOrWhiteSpace($script:dynamicPreviewServiceName)) {
        throw 'qualification_assertion_failed: dynamic preview cleanup fixture was not created.'
    }
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($script:dynamicPreviewServiceName)'" -ErrorAction SilentlyContinue
    Assert-Qualification ($null -ne $service) "Owned preview service $($script:dynamicPreviewServiceName) disappeared during upgrade."
    Assert-Qualification (Test-Path -LiteralPath (Join-Path $script:stateRoot "services\$($script:dynamicPreviewServiceName).json") -PathType Leaf) 'Owned preview declaration disappeared during upgrade.'
}

function Convert-ToMsiVersion {
    param([Parameter(Mandatory = $true)][string] $FullVersion)
    $parts = $FullVersion.Split('.')
    return '{0}.{1}.{2}' -f ([int]$parts[0] % 100), [int]$parts[1], (([int]$parts[2] * 100) + [int]$parts[3])
}

function Assert-Uninstalled {
    $services = Get-PaperboatServices
    Assert-Qualification ($services.Count -eq 0) "Paperboat SCM services remain after uninstall: $($services.Name -join ', ')."
    $previewServices = Get-PaperboatPreviewServices
    Assert-Qualification ($previewServices.Count -eq 0) "PaperboatPreview-* services remain after uninstall: $($previewServices.Name -join ', ')."
    if (-not [string]::IsNullOrWhiteSpace($script:dynamicPreviewServiceName)) {
        Assert-Qualification (-not (Test-Path -LiteralPath (Join-Path $script:stateRoot "services\$($script:dynamicPreviewServiceName).json"))) 'The owned preview service declaration remains after uninstall.'
    }
    Assert-Qualification (-not (Test-Path -LiteralPath $script:installRoot)) "Install root remains after uninstall: $($script:installRoot)"
    if (Test-Path -LiteralPath $script:registryPath) {
        $registry = Get-ItemProperty -LiteralPath $script:registryPath -ErrorAction SilentlyContinue
        Assert-Qualification ($null -eq $registry.ReleaseVersion) 'Paperboat ReleaseVersion remains after uninstall.'
    }
    if (Test-Path -LiteralPath $script:stateRoot) {
        $productFiles = @(Get-ChildItem -LiteralPath $script:stateRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -in @('provisioning-hook.json', 'paperboat-runtime.exe', 'paperboat-hostd.exe', 'paperboat-updater.exe')
        })
        Assert-Qualification ($productFiles.Count -eq 0) 'Product binaries or provisioning metadata remain in ProgramData after uninstall.'
    }
    $paperboatSshd = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'PaperboatSshd' })
    if ($null -ne $script:preexistingPaperboatSshd -and $script:preexistingPaperboatSshd.Count -gt 0) {
        Assert-Qualification ($paperboatSshd.Count -eq 1) 'Pre-existing PaperboatSshd was removed or duplicated by MSI uninstall.'
        Assert-Qualification ($paperboatSshd[0].PathName -eq $script:preexistingPaperboatSshd[0].PathName) 'Pre-existing PaperboatSshd configuration changed during MSI uninstall.'
    } else {
        Assert-Qualification ($paperboatSshd.Count -eq 0) 'PaperboatSshd was left behind by MSI uninstall without a pre-existing service.'
    }
    Assert-Qualification (@(Get-InstalledPaperboatProducts).Count -eq 0) 'An ARP Paperboat product entry remains after uninstall.'
    $machinePathEntries = @(Get-MachinePathEntries)
    $expectedPathEntry = ConvertTo-NormalizedMachinePathEntry $script:binaryRoot
    $paperboatPathEntryCount = @($machinePathEntries | Where-Object { $_ -ieq $expectedPathEntry }).Count
    Assert-Qualification ($paperboatPathEntryCount -eq 0) "Paperboat bin remains in the machine PATH after uninstall; found $paperboatPathEntryCount normalized entries for $expectedPathEntry."
    Add-QualificationEvent -Name 'msi_uninstall_assertions' -Status 'passed' -Detail 'fixed services, dynamic preview services, PATH ownership, PaperboatSshd ownership preservation, binaries, product registry, ARP entry, and provisioning metadata were verified.'
}

function Invoke-GoQualification {
    $repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
    $previousFixture = $env:PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE
    $env:PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE = $resolvedFixturePath
    try {
        Push-Location $repositoryRoot
        try {
            Add-QualificationEvent -Name 'native_go_e2e' -Status 'started' -Detail 'SCM hostd/updater, durable preview, and ConPTY tests'
            if ($NativeTestExecutable -ne '') {
                $resolvedNativeTestExecutable = [IO.Path]::GetFullPath($NativeTestExecutable)
                Assert-Qualification (Test-Path -LiteralPath $resolvedNativeTestExecutable -PathType Leaf) "Native Windows qualification test executable is missing: $resolvedNativeTestExecutable"
                $nativeTestArguments = @('-test.v', '-test.run', '^TestNative', '-test.count', '1', '-test.timeout', '5m')
                & $resolvedNativeTestExecutable @nativeTestArguments
            }
            else {
                & go test -count=1 -tags paperboat_native_e2e -v ./packaging/windows/e2e
            }
            Assert-Qualification ($LASTEXITCODE -eq 0) "Native Windows qualification Go tests failed with exit code $LASTEXITCODE."
            Add-QualificationEvent -Name 'native_go_e2e' -Status 'passed' -Detail 'SCM hostd/updater, durable preview, and ConPTY tests'
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE = $previousFixture
    }
}

function Write-QualificationReport {
    param([string] $Failure = '')
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $windowsBuild = [string]$operatingSystem.BuildNumber
    $runner = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_NAME)) { $env:RUNNER_NAME } else { $env:COMPUTERNAME }
    $report = [ordered]@{
        schema = 'paperboat.windows-native-qualification-report/v1'
        platform = 'windows'
        architecture = $Architecture
        stability = if ($Architecture -eq 'amd64') { 'stable' } else { 'beta' }
        native_tested = $true
        version = $Version
        status = if ($Failure -eq '') { 'passed' } else { 'failed' }
        windows_build = $windowsBuild
        runner = $runner
        upgrade_version = $UpgradeVersion
        msi_sha256 = if (Test-Path -LiteralPath $resolvedMsiPath) { (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedMsiPath).Hash.ToLowerInvariant() } else { $null }
        upgrade_msi_sha256 = if (Test-Path -LiteralPath $resolvedUpgradeMsiPath) { (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedUpgradeMsiPath).Hash.ToLowerInvariant() } else { $null }
        events = $script:events
        failure = if ($Failure -eq '') { $null } else { $Failure }
    }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    if ($env:GITHUB_STEP_SUMMARY) {
        @(
            "### Native Windows $Architecture qualification",
            "- Native tested: true",
            "- MSI lifecycle: fresh install, repair, upgrade, uninstall",
            "- SCM: PaperboatHostd, PaperboatUpdated, durable preview install/restart/expiry/uninstall",
            "- Terminal: PowerShell 5.1, PowerShell 7, cmd.exe, native ConPTY",
            "- Report: $reportPath"
        ) | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
        if ($Failure -ne '') {
            "- Result: failed" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
        }
    }
}

try {
    Assert-Preflight
    Invoke-GoQualification
    Stage-MsiPathFixtures

    $freshLog = Join-Path $resolvedOutputDirectory 'msi-fresh.log'
    Invoke-Msi -Arguments @('/i', (Quote-WindowsArgument $script:qualifiedFreshMsiPath)) -LogPath $freshLog -Operation 'fresh_install'
    $script:installedByHarness = $true
    Assert-InstalledPayload -ExpectedVersion $Version

    $repairTarget = Join-Path $script:binaryRoot 'pb.exe'
    Remove-Item -LiteralPath $repairTarget -Force
    Assert-Qualification (-not (Test-Path -LiteralPath $repairTarget)) 'Repair precondition did not remove pb.exe.'
    $repairLog = Join-Path $resolvedOutputDirectory 'msi-repair.log'
    Invoke-Msi -Arguments @('/fa', (Quote-WindowsArgument $script:qualifiedFreshMsiPath)) -LogPath $repairLog -Operation 'repair'
    Assert-Qualification (Test-Path -LiteralPath $repairTarget -PathType Leaf) 'MSI repair did not restore pb.exe.'
    Assert-InstalledPayload -ExpectedVersion $Version
    Add-QualificationEvent -Name 'msi_repair_assertions' -Status 'passed' -Detail 'removed pb.exe was restored and service/state contracts remained intact'

    New-OwnedPreviewCleanupFixture

    $upgradeLog = Join-Path $resolvedOutputDirectory 'msi-upgrade.log'
    Invoke-Msi -Arguments @('/i', (Quote-WindowsArgument $script:qualifiedUpgradeMsiPath)) -LogPath $upgradeLog -Operation 'upgrade'
    $script:upgradeInstalled = $true
    Assert-InstalledPayload -ExpectedVersion $UpgradeVersion
    Assert-OwnedPreviewCleanupFixturePresent
    $expectedMsiVersion = Convert-ToMsiVersion -FullVersion $UpgradeVersion
    $arpEntries = @(Get-InstalledPaperboatProducts)
    Assert-Qualification ($arpEntries.Count -eq 1) "Expected one ARP entry after upgrade, found $($arpEntries.Count)."
    Assert-Qualification ($arpEntries[0].DisplayVersion -eq $expectedMsiVersion) "ARP DisplayVersion=$($arpEntries[0].DisplayVersion), expected $expectedMsiVersion."
    Add-QualificationEvent -Name 'msi_upgrade_assertions' -Status 'passed' -Detail "version=$UpgradeVersion; arp_version=$expectedMsiVersion; single_product_entry=true"

    $productCode = $arpEntries[0].PSChildName
    Assert-Qualification ($productCode -match '^\{[0-9A-Fa-f-]+\}$') "ARP product code is invalid: $productCode"
    $uninstallLog = Join-Path $resolvedOutputDirectory 'msi-uninstall.log'
    Invoke-Msi -Arguments @('/x', $productCode) -LogPath $uninstallLog -Operation 'uninstall'
    $script:installedByHarness = $false
    $script:upgradeInstalled = $false
    Assert-Uninstalled

    $reinstallLog = Join-Path $resolvedOutputDirectory 'msi-reinstall.log'
    Invoke-Msi -Arguments @('/i', (Quote-WindowsArgument $script:qualifiedFreshMsiPath)) -LogPath $reinstallLog -Operation 'reinstall'
    $script:installedByHarness = $true
    Assert-InstalledPayload -ExpectedVersion $Version
    $reinstallEntries = @(Get-InstalledPaperboatProducts)
    Assert-Qualification ($reinstallEntries.Count -eq 1) "Expected one ARP entry after reinstall, found $($reinstallEntries.Count)."
    $reinstallUninstallLog = Join-Path $resolvedOutputDirectory 'msi-reinstall-uninstall.log'
    Invoke-Msi -Arguments @('/x', $reinstallEntries[0].PSChildName) -LogPath $reinstallUninstallLog -Operation 'reinstall_uninstall'
    $script:installedByHarness = $false
    Assert-Uninstalled
    Add-QualificationEvent -Name 'msi_reinstall_assertions' -Status 'passed' -Detail 'clean reinstall and second uninstall passed from a path containing spaces and Unicode'
}
catch {
    $failure = $_.Exception.Message
    Add-QualificationEvent -Name 'qualification' -Status 'failed' -Detail $failure
    throw
}
finally {
    if ($script:installedByHarness -or $script:upgradeInstalled) {
        try {
            $entries = @(Get-InstalledPaperboatProducts)
            if ($entries.Count -gt 0) {
                $cleanupCode = $entries[0].PSChildName
                $cleanupLog = Join-Path $resolvedOutputDirectory 'msi-cleanup.log'
                Invoke-Msi -Arguments @('/x', $cleanupCode) -LogPath $cleanupLog -Operation 'failure_cleanup'
            }
        }
        catch {
            Add-QualificationEvent -Name 'failure_cleanup' -Status 'failed' -Detail $_.Exception.Message
        }
    }
    $failureText = ($script:events | Where-Object { $_.status -eq 'failed' } | Select-Object -First 1).detail
    Write-QualificationReport -Failure $failureText
}
