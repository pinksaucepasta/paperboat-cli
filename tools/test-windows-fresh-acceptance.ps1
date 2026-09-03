<#
.SYNOPSIS
    Runs the disposable Windows host acceptance checklist.

.DESCRIPTION
    The default phase is Audit and never changes files, services, scheduled
    tasks, credentials, or release state. Fresh, Full, and Update phases are
    deliberately mutation-gated: they require -ExecuteMutation and the exact
    -Confirmation value below. Fresh enrollment accepts either a protected file
    containing a raw token (legacy) or a protected file containing the
    dashboard-generated p= field, URL, or command. Enrollment material is never
    placed in output or diagnostics.

    Run on a disposable Windows machine from an elevated PowerShell prompt:

      # Read-only preflight. It reports clean absence or audits an existing
      # Paperboat installation without changing anything.
      .\test-windows-fresh-acceptance.ps1 -Phase Audit

      # Fresh enrollment, restart identity check, update convergence, and
      # post-update health checks. The dashboard command file remains caller-owned.
      .\test-windows-fresh-acceptance.ps1 -Phase Full `
        -EnrollmentBootstrapFile C:\secure\paperboat-enrollment-command.txt `
        -ExecuteMutation `
        -Confirmation RUN-FRESH-WINDOWS-ACCEPTANCE

    The script does not perform cleanup automatically. After a successful
    run, inspect the printed cleanup boundary and use the product's supported
    unpair/uninstall flow separately if the disposable machine is to be reset.

.NOTES
    This is an acceptance harness, not an installer replacement. It invokes
    the repository's signed tools/install.ps1 and the installed pb commands.
    It intentionally does not accept a token value as a PowerShell parameter.
    EnrollmentBootstrapFile also accepts the aliases EnrollmentURLFile and
    EnrollmentCommandFile.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Fresh', 'Full', 'Update')]
    [string]$Phase = 'Audit',

    [string]$PbPath = '',
    [string]$InstallerPath = '',
    [string]$Server = 'https://api.pprbt.dev',
    [string]$ReleaseMetadataUrl = '',
    [string]$ExpectedVersion = '',
    [string]$MachineName = '',
    [ValidateSet('host', 'client')]
    [string]$SetupMode = '',
    [string]$EnrollmentTokenFile = '',
    [Alias('EnrollmentURLFile', 'EnrollmentCommandFile')]
    [string]$EnrollmentBootstrapFile = '',
    [int]$ReadinessTimeoutSeconds = 90,
    [int]$UpdateTimeoutSeconds = 300,
    [switch]$ExecuteMutation,
    [string]$Confirmation = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Variable -Name ScriptRoot -Value (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Variable -Name RequiredConfirmation -Value 'RUN-FRESH-WINDOWS-ACCEPTANCE'
# Runtime role declarations live under ServicesRoot. PaperboatSshd is a
# separately-owned OpenSSH declaration under ProgramData\Paperboat\ssh and is
# validated by the host-role readiness check below.
Set-Variable -Name ExpectedServiceNames -Value @('PaperboatHostd', 'PaperboatLocalDaemon', 'PaperboatUpdated')
Set-Variable -Name OwnedServiceNames -Value @(
    'PaperboatSshd', 'PaperboatHostd', 'PaperboatLocalDaemon', 'PaperboatUpdated',
    'PaperboatHost', 'PaperboatRuntimeConfig', 'PaperboatRuntime'
)

function Fail([string]$Message) {
    throw $Message
}

function Check([string]$Message) {
    Write-Output ("[ok] " + $Message)
}

function Require-PositiveTimeouts {
    if ($ReadinessTimeoutSeconds -lt 1 -or $ReadinessTimeoutSeconds -gt 600) {
        Fail 'ReadinessTimeoutSeconds must be between 1 and 600.'
    }
    if ($UpdateTimeoutSeconds -lt 1 -or $UpdateTimeoutSeconds -gt 1800) {
        Fail 'UpdateTimeoutSeconds must be between 1 and 1800.'
    }
}

function Require-Windows {
    if ($env:OS -ne 'Windows_NT') {
        Fail 'This acceptance harness must run on Windows.'
    }
    if ($Server -notmatch '^https://[^/]+(?:/.*)?$') {
        Fail 'Server must be an HTTPS URL.'
    }
}

function Get-PaperboatPaths {
    if ([string]::IsNullOrWhiteSpace($env:ProgramFiles) -or [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        Fail 'Windows Program Files or ProgramData is unavailable.'
    }
    $programFilesRoot = Join-Path $env:ProgramFiles 'Paperboat'
    $programDataRoot = Join-Path $env:ProgramData 'Paperboat'
    $openSSHRoot = Join-Path $env:ProgramFiles 'OpenSSH'
    $sshStateRoot = Join-Path $programDataRoot 'ssh'
    $localAppDataRoot = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { '' } else { Join-Path $env:LOCALAPPDATA 'Paperboat' }
    $roamingAppDataRoot = if ([string]::IsNullOrWhiteSpace($env:APPDATA)) { '' } else { Join-Path $env:APPDATA 'Paperboat' }
    [pscustomobject]@{
        InstallRoot       = $programFilesRoot
        Binary            = Join-Path $programFilesRoot 'bin\pb.exe'
        ReleasesRoot      = Join-Path $programFilesRoot 'releases'
        ProgramDataRoot   = $programDataRoot
        InstallConfig     = Join-Path $programDataRoot 'runtime-install.json'
        TokenFile         = Join-Path $programDataRoot 'hostd.token'
        ServicesRoot      = Join-Path $programDataRoot 'services'
        LifecycleRoot     = Join-Path $programDataRoot 'service-lifecycle'
        UpdateRoot        = Join-Path $programDataRoot 'updated'
        OpenSSHRoot       = $openSSHRoot
        SSHDPath          = Join-Path $openSSHRoot 'sshd.exe'
        SSHStateRoot      = $sshStateRoot
        SSHConfig         = Join-Path $sshStateRoot 'sshd_config'
        LocalAppDataRoot  = $localAppDataRoot
        RoamingAppDataRoot = $roamingAppDataRoot
    }
}

function Test-ReparsePoint([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-SafeOwnedRoot([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path -ne [IO.Path]::GetFullPath($Path)) {
        Fail 'A Paperboat-owned path is not an absolute clean path.'
    }
    if (Test-ReparsePoint $Path) {
        Fail 'A Paperboat-owned path is a reparse point.'
    }
}

function Get-ServiceRecord([string]$Name) {
    # The names are constants from the Windows installation contract, so the
    # WMI filter cannot be influenced by enrollment input.
    return Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction SilentlyContinue
}

function Get-OwnedServiceRecords {
    $records = @{}
    foreach ($name in $OwnedServiceNames) {
        $records[$name] = Get-ServiceRecord $name
    }
    return $records
}

function Get-OwnedLegacyTasks {
    $tasks = @()
    try {
        $tasks = @(Get-ScheduledTask -TaskPath '\Paperboat\' -ErrorAction SilentlyContinue)
    } catch {
        # Task Scheduler is not required for the current SCM service path. A
        # failed enumeration is not evidence of a legacy task, so the service
        # and fixed-path checks remain authoritative.
        return @()
    }
    return @($tasks | Where-Object {
        [string]$_.TaskName -match '^LocalDaemon-[0-9A-Fa-f]{16}$'
    })
}

function Assert-NoPaperboatProcesses([pscustomobject]$Paths) {
    $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='pb.exe'" -ErrorAction Stop)
    foreach ($process in $processes) {
        $executable = [string]$process.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($executable)) {
            continue
        }
        if ($executable.StartsWith($Paths.InstallRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            Fail 'A Paperboat executable is still running during clean preflight.'
        }
    }
}

function Assert-CleanAbsence([pscustomobject]$Paths) {
    $records = Get-OwnedServiceRecords
    foreach ($name in $OwnedServiceNames) {
        if ($null -ne $records[$name]) {
            Fail 'A Paperboat-owned Windows service already exists during clean preflight.'
        }
    }
    if ((Get-OwnedLegacyTasks).Count -ne 0) {
        Fail 'A retired Paperboat scheduled task already exists during clean preflight.'
    }
    Assert-NoPaperboatProcesses $Paths
    foreach ($path in @(
        $Paths.InstallRoot, $Paths.ProgramDataRoot,
        $Paths.LocalAppDataRoot, $Paths.RoamingAppDataRoot
    )) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
            Fail 'Paperboat-owned state is not absent during clean preflight.'
        }
    }
    $machinePath = [string][Environment]::GetEnvironmentVariable('Path', 'Machine')
    foreach ($entry in @($machinePath -split ';')) {
        if ([string]::Equals($entry.Trim().Trim('"'), (Join-Path $Paths.InstallRoot 'bin'), [StringComparison]::OrdinalIgnoreCase)) {
            Fail 'The Paperboat machine PATH entry remains during clean preflight.'
        }
    }
    $helperRoot = Join-Path $env:TEMP 'Paperboat Uninstall'
    if (Test-Path -LiteralPath $helperRoot) {
        $helperEntries = @(Get-ChildItem -LiteralPath $helperRoot -Force -ErrorAction Stop)
        if ($helperEntries.Count -ne 0) {
            Fail 'Paperboat uninstall helper residue remains during clean preflight.'
        }
    }
    Check 'clean absence: services, retired tasks, processes, PATH, helper state, and owned roots'
}

function Read-InstallConfig([pscustomobject]$Paths) {
    if (-not (Test-Path -LiteralPath $Paths.InstallConfig -PathType Leaf)) {
        Fail 'Windows runtime installation metadata is missing.'
    }
    if (Test-ReparsePoint $Paths.InstallConfig) {
        Fail 'Windows runtime installation metadata is a reparse point.'
    }
    try {
        $config = Get-Content -LiteralPath $Paths.InstallConfig -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Fail 'Windows runtime installation metadata is not valid JSON.'
    }
    if ([string]$config.schema -ne 'paperboat.windows-runtime-install/v1' -or
        -not [bool]$config.committed -or
        [string]$config.token_file -ne $Paths.TokenFile -or
        [string]$config.machine_id -eq '' -or
        [string]$config.owner_sid -eq '' -or
        ([string]$config.setup_mode -ne 'host' -and [string]$config.setup_mode -ne 'client') -or
        [string]$config.listen_address -eq '' -or
        [string]$config.state_root -eq '') {
        Fail 'Windows runtime installation metadata failed its strict acceptance checks.'
    }
    if (-not [IO.Path]::IsPathRooted([string]$config.state_root) -or
        [string]$config.state_root -ne [IO.Path]::GetFullPath([string]$config.state_root)) {
        Fail 'Windows runtime state root is not an absolute clean path.'
    }
    return $config
}

function Assert-ServiceRecord([string]$Name, [string]$Argument, [pscustomobject]$Paths, [bool]$RequireRunning) {
    $service = Get-ServiceRecord $Name
    if ($null -eq $service) {
        Fail 'An expected Paperboat Windows service is missing.'
    }
    $expectedCommand = '"' + $Paths.Binary + '" ' + $Argument
    if ([string]$service.PathName -ne $expectedCommand) {
        Fail 'A Paperboat Windows service points at an unexpected executable or role.'
    }
    if ([string]$service.StartMode -ne 'Auto') {
        Fail 'A Paperboat Windows service is not configured for automatic start.'
    }
    if ([string]$service.ServiceStartName -ine 'LocalSystem') {
        Fail 'A Paperboat Windows service is not configured for the LocalSystem boundary.'
    }
    if ($RequireRunning -and [string]$service.State -ne 'Running') {
        Fail 'An expected Paperboat Windows service is not running.'
    }
    if ($RequireRunning) {
        if ([uint32]$service.ProcessId -eq 0) {
            Fail 'An expected Paperboat Windows service has no live process.'
        }
        try {
            $process = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId={0}' -f [uint32]$service.ProcessId) -ErrorAction Stop) | Select-Object -First 1
        } catch {
            Fail 'An expected Paperboat Windows service process could not be inspected.'
        }
        if ($null -eq $process -or
            -not [string]::Equals([string]$process.ExecutablePath, [string]$Paths.Binary, [StringComparison]::OrdinalIgnoreCase)) {
            Fail 'An expected Paperboat Windows service is running an unexpected executable.'
        }
    }
}

function Assert-ServiceSet([pscustomobject]$Paths, [bool]$RequireRunning) {
    Assert-ServiceRecord 'PaperboatHostd' '__runtime-hostd' $Paths $RequireRunning
    Assert-ServiceRecord 'PaperboatLocalDaemon' '__runtime-local-daemon' $Paths $RequireRunning
    Assert-ServiceRecord 'PaperboatUpdated' '__runtime-updated' $Paths $RequireRunning
    if ($RequireRunning) {
        Check 'PaperboatUpdated is persistent, active, and runs the unified pb __runtime-updated role'
    }
    foreach ($name in @('PaperboatHost', 'PaperboatRuntimeConfig', 'PaperboatRuntime')) {
        if ($null -ne (Get-ServiceRecord $name)) {
            Fail 'An obsolete or duplicate Paperboat Windows service is installed.'
        }
    }
    Check 'three managed roles are present with exact executable/argument ownership'
}

function Format-WindowsServiceArgument([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains('"')) {
        Fail 'A Windows service argument is empty or contains an unsafe quote.'
    }
    if ($Value.IndexOf(' ') -ge 0 -or $Value.IndexOf([char]9) -ge 0) {
        return '"' + $Value + '"'
    }
    return $Value
}

function Read-PaperboatSSHConfig([pscustomobject]$Paths) {
    Assert-SafeOwnedRoot $Paths.SSHStateRoot
    if (-not (Test-Path -LiteralPath $Paths.SSHConfig -PathType Leaf) -or (Test-ReparsePoint $Paths.SSHConfig)) {
        Fail 'The managed Paperboat OpenSSH configuration is missing or unsafe.'
    }
    try {
        $lines = @(Get-Content -LiteralPath $Paths.SSHConfig -ErrorAction Stop)
    } catch {
        Fail 'The managed Paperboat OpenSSH configuration could not be read.'
    }
    $ports = @()
    $addresses = @()
    foreach ($line in $lines) {
        $text = [string]$line
        if ($text -match '^\s*Port\s+([0-9]{1,5})\s*(?:#.*)?$') {
            $ports += [int]$Matches[1]
        }
        if ($text -match '^\s*ListenAddress\s+(\S+)\s*(?:#.*)?$') {
            $addresses += [string]$Matches[1]
        }
    }
    if ($ports.Count -ne 1 -or $ports[0] -lt 1 -or $ports[0] -gt 65535) {
        Fail 'The managed Paperboat OpenSSH configuration does not define exactly one valid port.'
    }
    $uniqueAddresses = @($addresses | Sort-Object -Unique)
    if ($uniqueAddresses.Count -ne 2 -or
        $uniqueAddresses -notcontains '127.0.0.1' -or $uniqueAddresses -notcontains '::1') {
        Fail 'The managed Paperboat OpenSSH configuration is not restricted to both loopback families.'
    }
    [pscustomobject]@{
        Port      = [int]$ports[0]
        Addresses = $uniqueAddresses
    }
}

function Assert-PaperboatSSH([pscustomobject]$Paths) {
    $sshConfig = Read-PaperboatSSHConfig $Paths
    if (-not (Test-Path -LiteralPath $Paths.SSHDPath -PathType Leaf) -or (Test-ReparsePoint $Paths.SSHDPath)) {
        Fail 'The approved Paperboat OpenSSH daemon binary is missing or unsafe.'
    }
    $service = Get-ServiceRecord 'PaperboatSshd'
    if ($null -eq $service) {
        Fail 'PaperboatSshd is missing from a host-mode installation.'
    }
    if ([string]$service.StartMode -ne 'Auto' -or [string]$service.ServiceStartName -ine 'LocalSystem') {
        Fail 'PaperboatSshd is not configured as an automatic LocalSystem service.'
    }
    if ([string]$service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) {
        Fail 'PaperboatSshd is not running with a live service process.'
    }
    $expectedCommand = (Format-WindowsServiceArgument $Paths.Binary) +
        ' __windows-sshd-service --sshd ' + (Format-WindowsServiceArgument $Paths.SSHDPath) +
        ' --config ' + (Format-WindowsServiceArgument $Paths.SSHConfig)
    if (-not [string]::Equals([string]$service.PathName, $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
        Fail 'PaperboatSshd points at an unexpected executable, daemon, or configuration.'
    }

    try {
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $sshConfig.Port -ErrorAction Stop)
    } catch {
        Fail 'PaperboatSshd listeners could not be inspected.'
    }
    if ($listeners.Count -eq 0) {
        Fail 'PaperboatSshd has no listening TCP endpoint.'
    }
    $seen = @{'127.0.0.1' = $false; '::1' = $false}
    foreach ($listener in $listeners) {
        $address = ([string]$listener.LocalAddress).Trim()
        if (-not $seen.ContainsKey($address)) {
            Fail 'PaperboatSshd exposes a non-loopback TCP listener.'
        }
        if ([uint32]$listener.OwningProcess -eq 0) {
            Fail 'PaperboatSshd has a listener without an owning process.'
        }
        try {
            $process = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId={0}' -f [uint32]$listener.OwningProcess) -ErrorAction Stop) | Select-Object -First 1
        } catch {
            Fail 'PaperboatSshd listener ownership could not be inspected.'
        }
        if ($null -eq $process -or
            -not [string]::Equals([string]$process.ExecutablePath, [string]$Paths.SSHDPath, [StringComparison]::OrdinalIgnoreCase)) {
            Fail 'PaperboatSshd listener is owned by an unexpected executable.'
        }
        if ([uint32]$process.ProcessId -ne [uint32]$service.ProcessId -and
            [uint32]$process.ParentProcessId -ne [uint32]$service.ProcessId) {
            Fail 'PaperboatSshd listener is not owned by the PaperboatSshd service process tree.'
        }
        $seen[$address] = $true
    }
    if (-not $seen['127.0.0.1'] -or -not $seen['::1']) {
        Fail 'PaperboatSshd does not listen on both 127.0.0.1 and ::1.'
    }
    Check ('PaperboatSshd is running with owned sshd.exe listeners on both loopback families at port ' + $sshConfig.Port)
}

function Assert-NoPaperboatSSH {
    if ($null -ne (Get-ServiceRecord 'PaperboatSshd')) {
        Fail 'PaperboatSshd must not be installed for a client-mode installation.'
    }
    $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='pb.exe'" -ErrorAction Stop)
    foreach ($process in $processes) {
        if ([string]$process.CommandLine -match '(?i)(^|\s)__windows-sshd-service(\s|$)') {
            Fail 'A Paperboat SSH service wrapper is still running for a client-mode installation.'
        }
    }
    Check 'client-mode installation has no PaperboatSshd service or orphan SSH wrapper'
}

function Assert-SSHHealth([pscustomobject]$Paths, [pscustomobject]$Config) {
    switch ([string]$Config.setup_mode) {
        'host' {
            Assert-PaperboatSSH $Paths
            return
        }
        'client' {
            Assert-NoPaperboatSSH
            return
        }
        default {
            Fail 'The installed setup role is not a recognized Windows host or client mode.'
        }
    }
}

function Get-ListenUri([pscustomobject]$Config) {
    $listen = ([string]$Config.listen_address).Trim()
    if ($listen -notmatch '^(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$') {
        Fail 'The installed runtime listen address is not a loopback address.'
    }
    $port = [int]$Matches[2]
    if ($port -lt 1 -or $port -gt 65535) {
        Fail 'The installed runtime listen port is invalid.'
    }
    $listenHost = $Matches[1]
    if ($listenHost.StartsWith('[')) {
        return 'http://' + $listenHost + ':' + $port + '/healthz'
    }
    return 'http://' + $listenHost + ':' + $port + '/healthz'
}

function Assert-Health([pscustomobject]$Config) {
    $uri = Get-ListenUri $Config
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 10 -MaximumRedirection 0
    } catch {
        Fail 'The installed runtime health endpoint did not respond.'
    }
    if ([int]$response.StatusCode -ne 200 -or
        [string]$response.Headers['Content-Type'] -notmatch '^application/json(?:;|$)') {
        Fail 'The installed runtime health endpoint returned an invalid status or content type.'
    }
    try {
        $body = ([string]$response.Content).Trim() | ConvertFrom-Json
    } catch {
        Fail 'The installed runtime health endpoint returned invalid JSON.'
    }
    if (-not [bool]$body.live -or @($body.PSObject.Properties).Count -ne 1) {
        Fail 'The installed runtime health endpoint did not return exactly { live: true }.'
    }
    Check 'authenticated runtime health: HTTP 200 application/json { live: true }'
}

function Invoke-PbProcess([string[]]$Arguments, [bool]$Json) {
    if (-not (Test-Path -LiteralPath $PbPath -PathType Leaf)) {
        Fail 'The requested pb executable is missing.'
    }
    if (Test-ReparsePoint $PbPath) {
        Fail 'The requested pb executable is a reparse point.'
    }
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('paperboat-acceptance-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
    $stdoutPath = Join-Path $scratch 'stdout'
    $stderrPath = Join-Path $scratch 'stderr'
    try {
        $process = Start-Process -FilePath $PbPath -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        if ($process.ExitCode -ne 0) {
            # Never include captured stderr. The command may carry identity or
            # server details that are not part of this harness's output contract.
            Fail 'A Paperboat command failed.'
        }
        $stdout = [string](Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue)
        if ($stdout.Length -gt 1048576) {
            Fail 'A Paperboat command returned an oversized response.'
        }
        if ($Json) {
            try {
                return $stdout | ConvertFrom-Json
            } catch {
                Fail 'A Paperboat command returned invalid JSON.'
            }
        }
        return [string]$stdout
    } finally {
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-JsonData($Envelope) {
    if ($null -ne $Envelope.PSObject.Properties['data']) {
        return $Envelope.data
    }
    return $Envelope
}

function Invoke-PbJson([string[]]$Arguments) {
    return Invoke-PbProcess $Arguments $true
}

function Assert-UpdaterHealth([pscustomobject]$Config, $Status = $null) {
    if ($null -eq $Status) {
        $envelope = Invoke-PbJson @('update', 'status', '--json')
        if ($null -eq $envelope -or
            $null -eq $envelope.PSObject.Properties['ok'] -or -not [bool]$envelope.ok) {
            Fail 'pb update status did not return a successful response.'
        }
        $Status = Get-JsonData $envelope
    }
    if ($null -eq $Status -or
        [string]$Status.cli_version -eq '' -or
        [string]$Status.runtime_version -eq '' -or
        -not [bool]$Status.runtime_available) {
        Fail 'PaperboatUpdated did not report an available runtime and CLI.'
    }
    if ([bool]$Status.activation_pending -or -not [string]::IsNullOrWhiteSpace([string]$Status.activation_failure)) {
        Fail 'PaperboatUpdated reports a pending or failed activation.'
    }
    if ([string]$Status.runtime_version -cne [string]$Config.artifact.version) {
        Fail 'PaperboatUpdated runtime version does not match committed installation metadata.'
    }
    if ($null -ne $Status.PSObject.Properties['supervisor'] -and
        $null -ne $Status.supervisor -and [bool]$Status.supervisor.maintenance_required) {
        Fail 'PaperboatUpdated reports that supervisor maintenance is still required.'
    }
    Check ('PaperboatUpdated is ready with runtime ' + [string]$Status.runtime_version + ' and no activation failure')
}

function Get-StatusMachine($Status, [pscustomobject]$Config) {
    $machines = @($Status.machines)
    if ($machines.Count -eq 0) {
        Fail 'pb status returned no machine.'
    }
    $machine = $null
    if (-not [string]::IsNullOrWhiteSpace($MachineName)) {
        $machine = @($machines | Where-Object { [string]$_.alias -ieq $MachineName }) | Select-Object -First 1
    }
    if ($null -eq $machine -and $machines.Count -eq 1) {
        $machine = $machines[0]
    }
    if ($null -eq $machine) {
        Fail 'pb status returned multiple machines and no exact machine name was supplied.'
    }
    if ([string]$machine.id -ne [string]$Config.machine_id) {
        Fail 'pb status machine identity does not match protected installation metadata.'
    }
    if (-not [bool]$machine.eligible -or [string]$machine.runtime_state -ne 'ready') {
        Fail 'The enrolled Windows machine is not eligible and runtime-ready.'
    }
    if (-not [string]::IsNullOrWhiteSpace($MachineName) -and [string]$machine.alias -ine $MachineName) {
        Fail 'The enrolled machine alias does not match the requested fresh-enrollment name.'
    }
    return $machine
}

function Get-IdentityFingerprint([pscustomobject]$Config) {
    $identityPath = Join-Path ([string]$Config.state_root) 'machine-identity.json'
    if (-not (Test-Path -LiteralPath $identityPath -PathType Leaf) -or (Test-ReparsePoint $identityPath)) {
        Fail 'The protected machine identity file is missing or unsafe.'
    }
    try {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $identityPath).Hash.ToLowerInvariant()
    } catch {
        Fail 'The protected machine identity could not be fingerprinted.'
    }
}

function Get-IdentitySnapshot([pscustomobject]$Paths) {
    $config = Read-InstallConfig $Paths
    $status = Invoke-PbJson @('status', '--json')
    $machine = Get-StatusMachine $status $config
    [pscustomobject]@{
        MachineID       = [string]$machine.id
        EnvironmentID   = [string]$machine.environment_id
        Alias           = [string]$machine.alias
        SetupMode       = [string]$config.setup_mode
        IdentityHash    = Get-IdentityFingerprint $config
        InstallVersion  = [string]$config.artifact.version
    }
}

function Assert-IdentityUnchanged($Before, $After, [string]$Boundary) {
    foreach ($field in @('MachineID', 'EnvironmentID', 'Alias', 'SetupMode', 'IdentityHash')) {
        if ([string]$Before.$field -cne [string]$After.$field) {
            Fail ('Machine identity changed across ' + $Boundary + '.')
        }
    }
    Check ('machine identity stable across ' + $Boundary)
}

function Assert-DoctorAndStatus([pscustomobject]$Paths) {
    $doctor = Invoke-PbJson @('doctor', '--json')
    if (-not [bool]$doctor.ok) {
        Fail 'pb doctor reported an unhealthy Windows installation.'
    }
    $config = Read-InstallConfig $Paths
    $null = Get-StatusMachine (Invoke-PbJson @('status', '--json')) $config
    Check 'pb doctor and pb status report a healthy eligible machine'
}

function Wait-ForHealthy([pscustomobject]$Paths, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $config = Read-InstallConfig $Paths
            Assert-ServiceSet $Paths $true
            Assert-SSHHealth $Paths $config
            Assert-Health $config
            Assert-UpdaterHealth $config
            Assert-DoctorAndStatus $Paths
            return
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    Fail 'Windows Paperboat services did not become healthy before the bounded deadline.'
}

function Assert-Installed([pscustomobject]$Paths) {
    $config = Read-InstallConfig $Paths
    if (-not (Test-Path -LiteralPath $Paths.Binary -PathType Leaf) -or (Test-ReparsePoint $Paths.Binary)) {
        Fail 'The installed Paperboat executable is missing or unsafe.'
    }
    if (-not (Test-Path -LiteralPath $Paths.TokenFile -PathType Leaf) -or (Test-ReparsePoint $Paths.TokenFile)) {
        Fail 'The installed Paperboat hostd token is missing or unsafe.'
    }
    foreach ($name in $ExpectedServiceNames) {
        $definition = Join-Path $Paths.ServicesRoot ($name + '.json')
        if (-not (Test-Path -LiteralPath $definition -PathType Leaf) -or (Test-ReparsePoint $definition)) {
            Fail 'A managed Paperboat service declaration is missing or unsafe.'
        }
    }
    Assert-ServiceSet $Paths $true
    Assert-SSHHealth $Paths $config
    Assert-Health $config
    Assert-UpdaterHealth $config
    Assert-DoctorAndStatus $Paths
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) {
        $versionOutput = Invoke-PbProcess @('--version') $false
        if ([string]$versionOutput -notmatch [regex]::Escape($ExpectedVersion)) {
            Fail 'The installed Paperboat executable reports an unexpected version.'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($SetupMode) -and [string]$config.setup_mode -cne $SetupMode) {
        Fail 'The installed setup role does not match the requested acceptance role.'
    }
    Check 'fresh installation metadata, binary, services, health, and identity are valid'
    return $config
}

function Read-EnrollmentToken([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Test-ReparsePoint $Path)) {
        Fail 'EnrollmentTokenFile must be an absolute regular non-reparse file.'
    }
    $token = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop).Trim()
    if ($token -notmatch '^[0-9A-Z]{26}$') {
        Fail 'EnrollmentTokenFile does not contain a valid enrollment token.'
    }
    return $token
}

function Read-EnrollmentBootstrap([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Test-ReparsePoint $Path)) {
        Fail 'EnrollmentBootstrapFile must be an absolute regular non-reparse file.'
    }
    try {
        $content = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop).Trim()
    } catch {
        Fail 'EnrollmentBootstrapFile could not be read.'
    }
    if ([string]::IsNullOrWhiteSpace($content) -or $content.Length -gt 16KB) {
        Fail 'EnrollmentBootstrapFile is empty or too large.'
    }

    # The dashboard intentionally emits an opaque hostname-bound p= value. Do
    # not parse or print that value; extract only the exact HTTPS endpoint from
    # either the URL itself, its p= field, or the dashboard's generated
    # PowerShell command.
    $urlMatches = [regex]::Matches($content, '(?i)https://get\.pprbt\.dev/install\?p=[A-Za-z0-9-]+')
    if ($urlMatches.Count -eq 1) {
        $url = $urlMatches[0].Value
    } elseif ($content -match '^p=([A-Za-z0-9-]+)$') {
        # A protected capture containing only the dashboard's p= field is also
        # accepted, which lets an operator avoid storing the whole command.
        $url = 'https://get.pprbt.dev/install?' + $content
    } else {
        Fail 'EnrollmentBootstrapFile must contain exactly one dashboard enrollment URL, p= field, or command.'
    }
    try {
        $uri = [Uri]::new($url)
    } catch {
        Fail 'The dashboard enrollment URL is invalid.'
    }
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne 'get.pprbt.dev' -or
        $uri.AbsolutePath -cne '/install' -or $uri.Fragment -ne '' -or
        $uri.Query -notmatch '^\?p=([A-Za-z0-9-]+)$') {
        Fail 'The dashboard enrollment URL is not an approved protected bootstrap endpoint.'
    }
    $parameter = $uri.Query.Substring(3)
    if ($parameter -notmatch '^(?:[0-9A-Z]{26}|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?-[0-9A-Z]{26})$') {
        Fail 'The dashboard enrollment URL has an invalid protected parameter.'
    }
    return $url
}

function Invoke-FreshBootstrapInstaller([string]$BootstrapURL) {
    $powershell = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershell -PathType Leaf) -or (Test-ReparsePoint $powershell)) {
        Fail 'Windows PowerShell executable is unavailable.'
    }
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('paperboat-dashboard-bootstrap-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
    $bootstrapPath = Join-Path $scratch 'bootstrap.ps1'
    $stdoutPath = Join-Path $scratch 'stdout'
    $stderrPath = Join-Path $scratch 'stderr'
    try {
        try {
            # The endpoint response contains the protected token preamble. It
            # stays in a private temporary file and is never sent as an argument
            # or included in output.
            $response = Invoke-WebRequest -UseBasicParsing -Uri $BootstrapURL -Headers @{ 'User-Agent' = 'PowerShell/PaperboatAcceptance' } -TimeoutSec 30 -MaximumRedirection 0 -ErrorAction Stop
        } catch {
            Fail 'The dashboard-generated protected bootstrap could not be fetched.'
        }
        $body = [string]$response.Content
        if ([string]::IsNullOrWhiteSpace($body) -or $body.Length -gt 1MB) {
            Fail 'The dashboard-generated protected bootstrap response is invalid.'
        }
        Set-Content -LiteralPath $bootstrapPath -Value $body -NoNewline -Encoding UTF8 -ErrorAction Stop
        if ((Test-ReparsePoint $bootstrapPath) -or -not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) {
            Fail 'The dashboard-generated protected bootstrap file is unsafe.'
        }
        $argumentLine = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ($bootstrapPath -replace '"', '\"') + '"'
        $process = Start-Process -FilePath $powershell -ArgumentList $argumentLine -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        if ($process.ExitCode -ne 0) {
            Fail 'The dashboard-generated protected bootstrap failed.'
        }
    } finally {
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
        $body = $null
        $response = $null
    }
    Check 'dashboard-generated protected bootstrap completed without exposing enrollment material'
}

function Invoke-FreshInstaller([pscustomobject]$Paths) {
    if (-not $ExecuteMutation -or $Confirmation -cne $RequiredConfirmation) {
        Fail ('Fresh enrollment is mutation-gated. Supply -ExecuteMutation and -Confirmation ' + $RequiredConfirmation + '.')
    }
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile) -and -not [string]::IsNullOrWhiteSpace($EnrollmentBootstrapFile)) {
        Fail 'Supply only one of EnrollmentTokenFile or EnrollmentBootstrapFile.'
    }
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentBootstrapFile)) {
        Invoke-FreshBootstrapInstaller (Read-EnrollmentBootstrap $EnrollmentBootstrapFile)
        return
    }
    if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
        $InstallerPath = Join-Path $ScriptRoot 'install.ps1'
    }
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf) -or (Test-ReparsePoint $InstallerPath)) {
        Fail 'The Windows bootstrap installer script is missing or unsafe.'
    }
    $token = Read-EnrollmentToken $EnrollmentTokenFile
    $powershell = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershell -PathType Leaf)) {
        Fail 'Windows PowerShell executable is unavailable.'
    }
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('paperboat-installer-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
    $stdoutPath = Join-Path $scratch 'stdout'
    $stderrPath = Join-Path $scratch 'stderr'
    $oldValues = @{
        PAPERBOAT_ENROLLMENT_TOKEN = $env:PAPERBOAT_ENROLLMENT_TOKEN
        PAPERBOAT_SERVER = $env:PAPERBOAT_SERVER
        PAPERBOAT_MACHINE_NAME = $env:PAPERBOAT_MACHINE_NAME
        PAPERBOAT_VERSION = $env:PAPERBOAT_VERSION
        PAPERBOAT_RELEASE_METADATA_URL = $env:PAPERBOAT_RELEASE_METADATA_URL
    }
    $hadValues = @{
        PAPERBOAT_ENROLLMENT_TOKEN = Test-Path Env:PAPERBOAT_ENROLLMENT_TOKEN
        PAPERBOAT_SERVER = Test-Path Env:PAPERBOAT_SERVER
        PAPERBOAT_MACHINE_NAME = Test-Path Env:PAPERBOAT_MACHINE_NAME
        PAPERBOAT_VERSION = Test-Path Env:PAPERBOAT_VERSION
        PAPERBOAT_RELEASE_METADATA_URL = Test-Path Env:PAPERBOAT_RELEASE_METADATA_URL
    }
    try {
        # The token exists in this process only for the installer child and is
        # restored/removed in finally. It is never passed as an argument.
        $env:PAPERBOAT_ENROLLMENT_TOKEN = $token
        $env:PAPERBOAT_SERVER = $Server
        if (-not [string]::IsNullOrWhiteSpace($MachineName)) { $env:PAPERBOAT_MACHINE_NAME = $MachineName }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) { $env:PAPERBOAT_VERSION = $ExpectedVersion }
        if (-not [string]::IsNullOrWhiteSpace($ReleaseMetadataUrl)) { $env:PAPERBOAT_RELEASE_METADATA_URL = $ReleaseMetadataUrl }
        $argumentLine = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ($InstallerPath -replace '"', '\"') + '"'
        $process = Start-Process -FilePath $powershell -ArgumentList $argumentLine -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        if ($process.ExitCode -ne 0) {
            Fail 'The signed Windows bootstrap installer failed.'
        }
    } finally {
        Remove-Item Env:PAPERBOAT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
        foreach ($name in @('PAPERBOAT_SERVER', 'PAPERBOAT_MACHINE_NAME', 'PAPERBOAT_VERSION', 'PAPERBOAT_RELEASE_METADATA_URL')) {
            Remove-Item ("Env:" + $name) -ErrorAction SilentlyContinue
        }
        foreach ($name in $oldValues.Keys) {
            if ($hadValues[$name]) {
                Set-Item ("Env:" + $name) $oldValues[$name]
            }
        }
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
        $token = $null
    }
    Check 'signed bootstrap installer completed without exposing enrollment material'
}

function Restart-Hostd([pscustomobject]$Paths) {
    $service = Get-ServiceRecord 'PaperboatHostd'
    if ($null -eq $service) {
        Fail 'PaperboatHostd is missing before restart.'
    }
    try {
        Restart-Service -Name 'PaperboatHostd' -Force -ErrorAction Stop
    } catch {
        Fail 'PaperboatHostd restart failed.'
    }
    Wait-ForHealthy $Paths $ReadinessTimeoutSeconds
    Check 'PaperboatHostd restart completed with all roles healthy'
}

function Invoke-Update([pscustomobject]$Paths) {
    if (-not $ExecuteMutation -or $Confirmation -cne $RequiredConfirmation) {
        Fail ('Update is mutation-gated. Supply -ExecuteMutation and -Confirmation ' + $RequiredConfirmation + '.')
    }
    $result = Invoke-PbJson @('update', '--json')
    $data = Get-JsonData $result
    if ([string]$data.version -eq '') {
        Fail 'pb update returned no verified release version.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($UpdateTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $statusEnvelope = Invoke-PbJson @('update', 'status', '--json')
        $status = Get-JsonData $statusEnvelope
        if ([bool]$status.runtime_available -and [string]$status.activation_failure -eq '' -and -not [bool]$status.activation_pending) {
            $config = Read-InstallConfig $Paths
            Assert-ServiceSet $Paths $true
            Assert-SSHHealth $Paths $config
            Assert-Health $config
            Assert-UpdaterHealth $config $status
            Check 'signed updater path converged with no activation failure'
            return
        }
        Start-Sleep -Seconds 2
    }
    Fail 'The signed updater did not converge before the bounded deadline.'
}

function Assert-CleanupSafety([pscustomobject]$Paths) {
    foreach ($path in @(
        $Paths.InstallRoot, $Paths.ProgramDataRoot,
        $Paths.LocalAppDataRoot, $Paths.RoamingAppDataRoot
    )) {
        Assert-SafeOwnedRoot $path
    }
    $records = Get-OwnedServiceRecords
    foreach ($name in $OwnedServiceNames) {
        $record = $records[$name]
        if ($null -ne $record -and [string]$record.PathName -ne '' -and
            -not ([string]$record.PathName -like ('"' + $Paths.Binary + '"*'))) {
            Fail 'Cleanup safety found a Paperboat-named service owned by another executable.'
        }
    }
    foreach ($task in @(Get-OwnedLegacyTasks)) {
        if ([string]$task.TaskName -notmatch '^LocalDaemon-[0-9A-Fa-f]{16}$') {
            Fail 'Cleanup safety found a task outside the exact retired Paperboat namespace.'
        }
    }
    Check 'cleanup boundary is fixed, non-reparse, service-owned, and does not target broad Windows paths'
}

function Invoke-Audit([pscustomobject]$Paths) {
    $records = Get-OwnedServiceRecords
    $hasInstall = (Test-Path -LiteralPath $Paths.InstallConfig) -or (@($records.Values | Where-Object { $null -ne $_ }).Count -gt 0)
    if ($hasInstall) {
        Assert-Installed $Paths | Out-Null
    } else {
        Assert-CleanAbsence $Paths
    }
    Assert-CleanupSafety $Paths
    Check 'read-only audit completed'
}

function Invoke-Acceptance {
    Require-Windows
    Require-PositiveTimeouts
    $paths = Get-PaperboatPaths
    if ([string]::IsNullOrWhiteSpace($PbPath)) {
        $PbPath = Join-Path $paths.InstallRoot 'bin\pb.exe'
    }
    if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
        $InstallerPath = Join-Path $ScriptRoot 'install.ps1'
    }
    if (-not [IO.Path]::IsPathRooted($PbPath) -or $PbPath -ne [IO.Path]::GetFullPath($PbPath) -or
        -not [IO.Path]::IsPathRooted($InstallerPath) -or $InstallerPath -ne [IO.Path]::GetFullPath($InstallerPath)) {
        Fail 'PbPath and InstallerPath must be absolute clean paths.'
    }
    Assert-CleanupSafety $paths

    switch ($Phase) {
        'Audit' {
            Invoke-Audit $paths
            return
        }
        'Fresh' {
            Assert-CleanAbsence $paths
            Invoke-FreshInstaller $paths
            $null = Assert-Installed $paths
            return
        }
        'Full' {
            Assert-CleanAbsence $paths
            Invoke-FreshInstaller $paths
            $null = Assert-Installed $paths
            $beforeRestart = Get-IdentitySnapshot $paths
            Restart-Hostd $paths
            $afterRestart = Get-IdentitySnapshot $paths
            Assert-IdentityUnchanged $beforeRestart $afterRestart 'restart'
            Invoke-Update $paths
            $afterUpdate = Get-IdentitySnapshot $paths
            Assert-IdentityUnchanged $afterRestart $afterUpdate 'update'
            Assert-CleanupSafety $paths
            Check 'full Windows fresh acceptance completed'
            return
        }
        'Update' {
            if (-not $ExecuteMutation -or $Confirmation -cne $RequiredConfirmation) {
                Fail ('Update is mutation-gated. Supply -ExecuteMutation and -Confirmation ' + $RequiredConfirmation + '.')
            }
            $null = Assert-Installed $paths
            $beforeUpdate = Get-IdentitySnapshot $paths
            Invoke-Update $paths
            $afterUpdate = Get-IdentitySnapshot $paths
            Assert-IdentityUnchanged $beforeUpdate $afterUpdate 'update'
            Assert-CleanupSafety $paths
            Check 'Windows update acceptance completed'
            return
        }
    }
}

try {
    Invoke-Acceptance
} catch {
    Write-Error 'Windows Paperboat acceptance failed.'
    exit 1
}
