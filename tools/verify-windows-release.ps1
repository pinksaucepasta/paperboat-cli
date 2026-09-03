<#
.SYNOPSIS
    Performs a read-only post-install verification of a Windows Paperboat host.

.DESCRIPTION
    This script is the safe verification half of the Windows acceptance flow.
    It does not install, purge, repair, update, start, stop, restart, or reboot
    anything. It only reads fixed Paperboat paths, queries SCM, performs a
    loopback GET, and invokes read-only pb commands. Feature commands are
    printed for the operator and are never executed here.

    Run from an elevated PowerShell prompt on Victus after the dashboard's
    one-shot installation command has completed:

      powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
        -File .\verify-windows-release.ps1

    Add -ExpectedVersion YYYY.MM.DD.N when the release artifact version is known.

    Re-run the same command after a normal Windows restart. The script checks
    the persisted automatic-start and recovery declarations on every run. It
    deliberately does not reboot the machine itself.

.NOTES
    No enrollment token, bearer token, cookie, private key, command stderr, or
    full status JSON is printed. A failed check is recorded by name and the
    remaining independent checks continue, so one run produces a complete
    diagnostic result without repeated service restarts.
#>
[CmdletBinding()]
param(
    [string]$PbPath = '',
    [string]$ExpectedVersion = '',
    [ValidateRange(5, 120)]
    [int]$CommandTimeoutSeconds = 30,
    [ValidateRange(2, 60)]
    [int]$HealthTimeoutSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = New-Object 'System.Collections.Generic.List[string]'
$script:Passed = New-Object 'System.Collections.Generic.List[string]'
$script:ServiceNames = @('PaperboatHostd', 'PaperboatLocalDaemon', 'PaperboatUpdated')
$script:LegacyServiceNames = @('PaperboatHost', 'PaperboatRuntimeConfig', 'PaperboatRuntime')

function Add-Failure([string]$Name) {
    [void]$script:Failures.Add($Name)
    Write-Output ('[fail] ' + $Name)
}

function Add-Pass([string]$Name) {
    [void]$script:Passed.Add($Name)
    Write-Output ('[ok] ' + $Name)
}

function Invoke-ReadOnlyCheck([string]$Name, [scriptblock]$Action) {
    try {
        & $Action
        Add-Pass $Name
    } catch {
        # Do not print exception text. It can contain usernames, endpoints, or
        # implementation details that are not part of this verifier's output.
        Add-Failure $Name
    }
}

function Require-Windows {
    if ($env:OS -ne 'Windows_NT') {
        throw 'not Windows'
    }
    if ([string]::IsNullOrWhiteSpace($env:ProgramFiles) -or [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        throw 'missing Windows roots'
    }
    if ($CommandTimeoutSeconds -lt 5 -or $HealthTimeoutSeconds -lt 2) {
        throw 'invalid timeout'
    }
}

function Test-ReparsePoint([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Require-RegularFile([string]$Path, [long]$MaximumBytes) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Test-ReparsePoint $Path)) {
        throw 'missing or unsafe file'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Length -lt 1 -or $item.Length -gt $MaximumBytes) {
        throw 'invalid file'
    }
}

function Require-Directory([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Container) -or (Test-ReparsePoint $Path)) {
        throw 'missing or unsafe directory'
    }
}

function Get-PaperboatPaths {
    $programFilesRoot = Join-Path $env:ProgramFiles 'Paperboat'
    $programDataRoot = Join-Path $env:ProgramData 'Paperboat'
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
        SSHDPath          = Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'
        SSHStateRoot      = Join-Path $programDataRoot 'ssh'
        SSHConfig         = Join-Path $programDataRoot 'ssh\sshd_config'
    }
}

function Read-JsonFile([string]$Path, [long]$MaximumBytes) {
    Require-RegularFile $Path $MaximumBytes
    $body = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    try {
        return $body | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'invalid JSON'
    }
}

function Get-JsonValue($Object, [string]$Name) {
    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-JsonProperty($Object, [string]$Name) {
    if ($null -eq $Object) {
        return $null
    }
    return $Object.PSObject.Properties[$Name]
}

function Parse-LoopbackListenAddress([string]$ListenAddress, [string]$ErrorLabel) {
    $listenHost = $null
    $portText = $null
    if ($ListenAddress -match '^\[(?<host>[0-9A-Fa-f:.]+)\]:(?<port>[0-9]{1,5})$') {
        $listenHost = [string]$Matches['host']
        $portText = [string]$Matches['port']
    } elseif ($ListenAddress -match '^(?<host>[0-9]{1,3}(?:\.[0-9]{1,3}){3}):(?<port>[0-9]{1,5})$') {
        $listenHost = [string]$Matches['host']
        $portText = [string]$Matches['port']
    } else {
        throw $ErrorLabel
    }
    try {
        $ip = [System.Net.IPAddress]::Parse($listenHost)
        $port = [int]$portText
    } catch {
        throw $ErrorLabel
    }
    if (-not [System.Net.IPAddress]::IsLoopback($ip) -or $port -lt 1 -or $port -gt 65535) {
        throw $ErrorLabel
    }
    return [pscustomobject]@{ IP = $ip; Port = $port }
}

function Read-InstallConfig([pscustomobject]$Paths) {
    $config = Read-JsonFile $Paths.InstallConfig (128 * 1024)
    $schema = [string](Get-JsonValue $config 'schema')
    $committed = [bool](Get-JsonValue $config 'committed')
    $tokenFile = [string](Get-JsonValue $config 'token_file')
    $machineID = [string](Get-JsonValue $config 'machine_id')
    $ownerSID = [string](Get-JsonValue $config 'owner_sid')
    $stateRoot = [string](Get-JsonValue $config 'state_root')
    $listenAddress = [string](Get-JsonValue $config 'listen_address')
    $setupMode = [string](Get-JsonValue $config 'setup_mode')
    $artifact = Get-JsonValue $config 'artifact'
    $artifactVersion = [string](Get-JsonValue $artifact 'version')
    $artifactPlatform = [string](Get-JsonValue $artifact 'platform')
    $artifactArchitecture = [string](Get-JsonValue $artifact 'architecture')
    if ($schema -ne 'paperboat.windows-runtime-install/v1' -or -not $committed -or
        $tokenFile -ne $Paths.TokenFile -or [string]::IsNullOrWhiteSpace($machineID) -or
        [string]::IsNullOrWhiteSpace($ownerSID) -or [string]::IsNullOrWhiteSpace($stateRoot) -or
        ($setupMode -ne 'host' -and $setupMode -ne 'client') -or
        $artifactPlatform -ne 'windows' -or ($artifactArchitecture -ne 'amd64' -and $artifactArchitecture -ne 'arm64') -or
        $artifactVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') {
        throw 'invalid installation metadata'
    }
    if (-not [IO.Path]::IsPathRooted($stateRoot) -or [IO.Path]::GetFullPath($stateRoot) -ne $stateRoot) {
        throw 'invalid state root'
    }
    [void](Parse-LoopbackListenAddress $listenAddress 'invalid listen address')
    return $config
}

function Get-ServiceRecord([string]$Name) {
    $records = @(Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction SilentlyContinue)
    if ($records.Count -ne 1) {
        return $null
    }
    return $records[0]
}

function Assert-ServiceDefinition([pscustomobject]$Paths, [string]$Name, [string]$Argument) {
    $path = Join-Path $Paths.ServicesRoot ($Name + '.json')
    $definition = Read-JsonFile $path (64 * 1024)
    if ([string](Get-JsonValue $definition 'schema') -ne 'paperboat.windows-service/v1' -or
        [string](Get-JsonValue $definition 'name') -ine $Name -or
        [string](Get-JsonValue $definition 'executable') -ine $Paths.Binary) {
        throw 'invalid service declaration'
    }
    $arguments = @(Get-JsonValue $definition 'arguments')
    if ($arguments.Count -ne 1 -or [string]$arguments[0] -cne $Argument) {
        throw 'invalid service role argument'
    }
    if ([string]::IsNullOrWhiteSpace([string](Get-JsonValue $definition 'account'))) {
        throw 'invalid service account declaration'
    }
}

function Invoke-ScRead([string[]]$Arguments) {
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        throw 'missing Windows root'
    }
    $scPath = Join-Path $env:SystemRoot 'System32\sc.exe'
    Require-RegularFile $scPath (4 * 1024 * 1024)
    $output = @(& $scPath @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw 'SCM query failed'
    }
    return [string]::Join("`n", [string[]]$output)
}

function Assert-ServiceRecovery([string]$Name) {
    $failure = Invoke-ScRead @('qfailure', $Name)
    if ($failure -notmatch '(?i)RESTART' -or $failure -notmatch '5000' -or $failure -notmatch '15000' -or $failure -notmatch '60000') {
        throw 'standard restart recovery actions are missing'
    }
    $nonCrash = Invoke-ScRead @('qfailureflag', $Name)
    if ($nonCrash -notmatch '(?im)FAILURE_ACTIONS_ON_NONCRASH_FAILURES\s*:\s*(?:1|TRUE)') {
        throw 'non-crash recovery is disabled'
    }
}

function Assert-ServiceProcess([pscustomobject]$Paths, [string]$Name, [string]$Argument, [bool]$RequireRunning) {
    $service = Get-ServiceRecord $Name
    if ($null -eq $service) {
        throw 'service is missing'
    }
    $expectedCommand = '"' + $Paths.Binary + '" ' + $Argument
    if (-not [string]::Equals([string]$service.PathName, $expectedCommand, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$service.StartMode -ne 'Auto' -or [string]$service.StartName -ine 'LocalSystem') {
        throw 'service declaration does not match the installed Paperboat boundary'
    }
    Assert-ServiceDefinition $Paths $Name $Argument
    Assert-ServiceRecovery $Name
    if (-not $RequireRunning) {
        return
    }
    if ([string]$service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) {
        throw 'service is not running'
    }
    $process = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId={0}' -f [uint32]$service.ProcessId) -ErrorAction Stop) | Select-Object -First 1
    if ($null -eq $process -or -not [string]::Equals([string]$process.ExecutablePath, [string]$Paths.Binary, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'service process does not own the installed binary'
    }
}

function Assert-SSHService([pscustomobject]$Paths, [pscustomobject]$Config) {
    $sshName = 'PaperboatSshd'
    $service = Get-ServiceRecord $sshName
    if ([string]$Config.setup_mode -eq 'client') {
        if ($null -ne $service) {
            throw 'client mode unexpectedly has PaperboatSshd'
        }
        return
    }
    if ($null -eq $service) {
        throw 'host mode is missing PaperboatSshd'
    }
    Require-RegularFile $Paths.SSHDPath (64 * 1024 * 1024)
    Require-RegularFile $Paths.SSHConfig (64 * 1024)
    if ([string]$service.StartMode -ne 'Auto' -or [string]$service.StartName -ine 'LocalSystem' -or
        [string]$service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) {
        throw 'PaperboatSshd is not an automatic running LocalSystem service'
    }
    $expected = '"' + $Paths.Binary + '" __windows-sshd-service --sshd "' + $Paths.SSHDPath + '" --config ' + $Paths.SSHConfig
    if (-not [string]::Equals([string]$service.PathName, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PaperboatSshd command is not owned by Paperboat'
    }
}

function Assert-SCM([pscustomobject]$Paths, [pscustomobject]$Config, [bool]$RequireRunning) {
    Require-Directory $Paths.ServicesRoot
    foreach ($legacy in $script:LegacyServiceNames) {
        if ($null -ne (Get-ServiceRecord $legacy)) {
            throw 'retired duplicate Paperboat service exists'
        }
    }
    Assert-ServiceProcess $Paths 'PaperboatHostd' '__runtime-hostd' $RequireRunning
    Assert-ServiceProcess $Paths 'PaperboatLocalDaemon' '__runtime-local-daemon' $RequireRunning
    Assert-ServiceProcess $Paths 'PaperboatUpdated' '__runtime-updated' $RequireRunning
    Assert-SSHService $Paths $Config
}

function Get-HealthUri([pscustomobject]$Config) {
    $listenAddress = [string](Get-JsonValue $Config 'listen_address')
    $endpoint = Parse-LoopbackListenAddress $listenAddress 'invalid health address'
    if ($endpoint.IP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        return ('http://[' + $endpoint.IP.ToString() + ']:' + $endpoint.Port + '/healthz')
    }
    return ('http://' + $endpoint.IP.ToString() + ':' + $endpoint.Port + '/healthz')
}

function Assert-Health([pscustomobject]$Config) {
    $response = Invoke-WebRequest -UseBasicParsing -Uri (Get-HealthUri $Config) -TimeoutSec $HealthTimeoutSeconds -MaximumRedirection 0 -ErrorAction Stop
    if ([int]$response.StatusCode -ne 200 -or [string]$response.Headers['Content-Type'] -notmatch '^application/json(?:;|$)') {
        throw 'invalid health response'
    }
    $body = [string]$response.Content
    $value = $body | ConvertFrom-Json -ErrorAction Stop
    $live = Get-JsonValue $value 'live'
    $properties = @($value.PSObject.Properties)
    if (-not [bool]$live -or $properties.Count -ne 1 -or [string]$properties[0].Name -cne 'live') {
        throw 'invalid health body'
    }
}

function ConvertTo-ProcessArgument([string]$Argument) {
    if ($null -eq $Argument -or $Argument -notmatch '^[A-Za-z0-9_.:/-]+$') {
        throw 'unsafe verification argument'
    }
    return '"' + $Argument + '"'
}

function Invoke-PbProcess([string[]]$Arguments) {
    if (-not (Test-Path -LiteralPath $script:PbPath -PathType Leaf) -or (Test-ReparsePoint $script:PbPath)) {
        throw 'pb executable is missing or unsafe'
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $script:PbPath
    $startInfo.Arguments = [string]::Join(' ', [string[]]($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }))
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'pb process did not start'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($CommandTimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            throw 'pb command timed out'
        }
        $stdout = [string]$stdoutTask.Result
        $stderr = [string]$stderrTask.Result
        if ($stdout.Length -gt (1024 * 1024) -or $stderr.Length -gt (1024 * 1024)) {
            throw 'pb command output is oversized'
        }
        return [pscustomobject]@{ ExitCode = [int]$process.ExitCode; Stdout = $stdout }
    } finally {
        $process.Dispose()
    }
}

function Invoke-PbJson([string[]]$Arguments) {
    $result = Invoke-PbProcess $Arguments
    if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($result.Stdout)) {
        throw 'pb command failed'
    }
    try {
        return $result.Stdout | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'pb command returned invalid JSON'
    }
}

function Invoke-PbHelp([string[]]$Arguments) {
    $result = Invoke-PbProcess $Arguments
    if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($result.Stdout)) {
        throw 'pb help command failed'
    }
    return $result.Stdout
}

function Assert-Status([pscustomobject]$Config) {
    # pb status/doctor can attempt the product's normal local-daemon recovery
    # if its owner pipe is absent. Require the fixed pipe before invoking them
    # so this verifier never turns a diagnostic run into an install operation.
    if (-not (Test-Path -LiteralPath '\\.\pipe\paperboat-local-api')) {
        throw 'local Paperboat API pipe is absent'
    }
    $status = Invoke-PbJson @('status', '--json')
    $machines = @(Get-JsonValue $status 'machines')
    if ($machines.Count -eq 0) {
        throw 'status returned no machine'
    }
    $machineID = [string](Get-JsonValue $Config 'machine_id')
    $matches = @($machines | Where-Object { [string](Get-JsonValue $_ 'id') -ceq $machineID })
    if ($matches.Count -ne 1) {
        throw 'status machine identity does not match installation metadata'
    }
    $machine = $matches[0]
    if (-not [bool](Get-JsonValue $machine 'eligible') -or [string](Get-JsonValue $machine 'runtime_state') -ne 'ready') {
        throw 'status machine is not eligible and ready'
    }
}

function Assert-Doctor {
    if (-not (Test-Path -LiteralPath '\\.\pipe\paperboat-local-api')) {
        throw 'local Paperboat API pipe is absent'
    }
    $doctor = Invoke-PbJson @('doctor', '--json')
    if ([string](Get-JsonValue $doctor 'overall') -cne 'healthy') {
        throw 'doctor did not report healthy'
    }
}

function Get-EnvelopeData($Envelope) {
    $data = Get-JsonValue $Envelope 'data'
    if ($null -ne $data) {
        return $data
    }
    return $Envelope
}

function Assert-Updater([pscustomobject]$Config) {
    $envelope = Invoke-PbJson @('update', 'status', '--json')
    if (-not [bool](Get-JsonValue $envelope 'ok')) {
        throw 'updater status was not successful'
    }
    $status = Get-EnvelopeData $envelope
    $runtimeVersion = [string](Get-JsonValue $status 'runtime_version')
    $expectedVersion = [string](Get-JsonValue (Get-JsonValue $Config 'artifact') 'version')
    if ([string]::IsNullOrWhiteSpace([string](Get-JsonValue $status 'cli_version')) -or
        [string]::IsNullOrWhiteSpace($runtimeVersion) -or -not [bool](Get-JsonValue $status 'runtime_available') -or
        [bool](Get-JsonValue $status 'activation_pending') -or
        -not [string]::IsNullOrWhiteSpace([string](Get-JsonValue $status 'activation_failure')) -or
        $runtimeVersion -cne $expectedVersion) {
        throw 'updater status is not converged'
    }
    $supervisor = Get-JsonValue $status 'supervisor'
    if ($null -ne $supervisor -and [bool](Get-JsonValue $supervisor 'maintenance_required')) {
        throw 'updater supervisor requires maintenance'
    }
}

function Assert-UpdateCheck {
    $envelope = Invoke-PbJson @('update', 'check', '--json')
    if (-not [bool](Get-JsonValue $envelope 'ok')) {
        throw 'signed update check was not successful'
    }
    $data = Get-EnvelopeData $envelope
    if (-not [bool](Get-JsonValue $data 'verified') -or [string]::IsNullOrWhiteSpace([string](Get-JsonValue $data 'latest_version'))) {
        throw 'signed update metadata was not verified'
    }
}

function Assert-PageCommand([string[]]$Arguments, [string]$ItemProperty) {
    $page = Invoke-PbJson $Arguments
    if ($null -eq (Get-JsonProperty $page $ItemProperty)) {
        throw 'page command did not return its canonical items field'
    }
    [void]@(Get-JsonValue $page $ItemProperty)
}

function Assert-FeatureCommandSurface {
    $previewHelp = Invoke-PbHelp @('preview', '--help')
    if ($previewHelp -notmatch '(?m)preview <port\|url\|path>' -or $previewHelp -notmatch '(?m)\blist\b' -or $previewHelp -notmatch '(?m)\bstop\b') {
        throw 'preview command surface is not canonical'
    }
    $tunnelHelp = Invoke-PbHelp @('tunnel', '--help')
    foreach ($word in @('create', 'list', 'status', 'doctor', 'route', 'domain', 'connector')) {
        if ($tunnelHelp -notmatch ('(?m)\b' + $word + '\b')) {
            throw 'tunnel command surface is incomplete'
        }
    }
    $updateHelp = Invoke-PbHelp @('update', '--help')
    if ($updateHelp -notmatch '(?m)\bcheck\b' -or $updateHelp -notmatch '(?m)\bstatus\b') {
        throw 'update command surface is incomplete'
    }
}

function Assert-RuntimeState([pscustomobject]$Paths, [pscustomobject]$Config) {
    Require-Directory $Paths.ProgramDataRoot
    Require-Directory $Paths.LifecycleRoot
    Require-Directory $Paths.UpdateRoot
    Require-Directory $Paths.ReleasesRoot
    Require-RegularFile $Paths.Binary (512 * 1024 * 1024)
    Require-RegularFile $Paths.TokenFile 64
    if ((Get-Item -LiteralPath $Paths.TokenFile -Force).Length -ne 32) {
        throw 'hostd token has an invalid length'
    }
    $stateRoot = [string](Get-JsonValue $Config 'state_root')
    Require-Directory $stateRoot
    foreach ($name in @('machine-identity.json', 'machine-registration.json')) {
        Require-RegularFile (Join-Path $stateRoot $name) (256 * 1024)
    }
    foreach ($name in @('worker-local.json', 'local-control-token')) {
        Require-RegularFile (Join-Path $stateRoot ('runtime\' + $name)) (256 * 1024)
    }
}

function Assert-RebootPersistence([pscustomobject]$Paths, [pscustomobject]$Config) {
    if (-not [bool](Get-JsonValue $Config 'committed')) {
        throw 'installation metadata is not committed'
    }
    foreach ($role in @(
            [pscustomobject]@{ Name = 'PaperboatHostd'; Argument = '__runtime-hostd' },
            [pscustomobject]@{ Name = 'PaperboatLocalDaemon'; Argument = '__runtime-local-daemon' },
            [pscustomobject]@{ Name = 'PaperboatUpdated'; Argument = '__runtime-updated' })) {
        $service = Get-ServiceRecord $role.Name
        if ($null -eq $service -or [string]$service.StartMode -ne 'Auto' -or [string]$service.StartName -ine 'LocalSystem') {
            throw 'service is not persisted as automatic LocalSystem'
        }
        $expectedCommand = '"' + $Paths.Binary + '" ' + $role.Argument
        if (-not [string]::Equals([string]$service.PathName, $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'service command is not persisted at the canonical binary'
        }
        Assert-ServiceDefinition $Paths $role.Name $role.Argument
    }
    Require-RegularFile $Paths.InstallConfig (128 * 1024)
    Require-Directory $Paths.LifecycleRoot
    Require-Directory $Paths.UpdateRoot
}

function Write-FeatureCommands {
    Write-Output ''
    Write-Output 'Exact feature commands (printed only, not executed by this verifier):'
    Write-Output '  pb preview list --json'
    Write-Output '  pb preview 8080 --duration 5m --json'
    Write-Output '  pb preview 8080 --private --duration 5m --json'
    Write-Output '  pb preview stop <preview-id> --json'
    Write-Output '  pb tunnel list --json'
    Write-Output '  pb tunnel create win-smoke --port 8080 --private --wait --timeout 2m --json'
    Write-Output '  pb tunnel status win-smoke --json'
    Write-Output '  pb tunnel doctor win-smoke --json'
    Write-Output '  pb tunnel delete win-smoke --yes --wait --timeout 2m --json'
    Write-Output '  The preview/tunnel create commands are mutations and require a local fixture plus authenticated control-plane access.'
    Write-Output '  Re-run this verifier after a normal Windows restart to validate the persisted SCM declarations again; this script never reboots the machine.'
}

try {
    Require-Windows
    $paths = Get-PaperboatPaths
    if ([string]::IsNullOrWhiteSpace($PbPath)) {
        $script:PbPath = $paths.Binary
    } else {
        if (-not [IO.Path]::IsPathRooted($PbPath) -or [IO.Path]::GetFullPath($PbPath) -ne $PbPath) {
            throw 'PbPath must be absolute and clean'
        }
        $script:PbPath = $PbPath
    }
    Require-RegularFile $script:PbPath (512 * 1024 * 1024)
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) {
        if ($ExpectedVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') {
            throw 'ExpectedVersion is invalid'
        }
    }
} catch {
    Write-Error 'Windows Paperboat verifier could not initialize.'
    exit 1
}

$config = $null
Invoke-ReadOnlyCheck 'installation metadata' {
    $script:config = Read-InstallConfig $paths
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion) -and
        [string](Get-JsonValue (Get-JsonValue $script:config 'artifact') 'version') -cne $ExpectedVersion) {
        throw 'installed version differs from requested version'
    }
}
$config = $script:config

Invoke-ReadOnlyCheck 'canonical SCM services, paths, automatic start, and recovery' {
    if ($null -eq $config) { throw 'installation metadata unavailable' }
    Assert-SCM $paths $config $true
}

Invoke-ReadOnlyCheck 'reboot persistence declarations' {
    if ($null -eq $config) { throw 'installation metadata unavailable' }
    Assert-RebootPersistence $paths $config
}

Invoke-ReadOnlyCheck 'protected runtime state and updater layout' {
    if ($null -eq $config) { throw 'installation metadata unavailable' }
    Assert-RuntimeState $paths $config
}

Invoke-ReadOnlyCheck 'loopback hostd health' {
    if ($null -eq $config) { throw 'installation metadata unavailable' }
    Assert-Health $config
}

Invoke-ReadOnlyCheck 'pb status' {
    if ($null -eq $config) { throw 'installation metadata unavailable' }
    Assert-Status $config
}

Invoke-ReadOnlyCheck 'pb doctor' {
    Assert-Doctor
}

Invoke-ReadOnlyCheck 'pb update status' {
    if ($null -eq $config) { throw 'installation metadata unavailable' }
    Assert-Updater $config
}

Invoke-ReadOnlyCheck 'pb update check signature path' {
    Assert-UpdateCheck
}

Invoke-ReadOnlyCheck 'preview command surface and read-only list' {
    Assert-FeatureCommandSurface
    Assert-PageCommand @('preview', 'list', '--json') 'items'
}

Invoke-ReadOnlyCheck 'tunnel command surface and read-only list' {
    Assert-PageCommand @('tunnel', 'list', '--json') 'items'
}

if ($null -ne $config) {
    Write-Output ('[info] installed Paperboat version: ' + [string](Get-JsonValue (Get-JsonValue $config 'artifact') 'version'))
    Write-Output ('[info] installed setup mode: ' + [string](Get-JsonValue $config 'setup_mode'))
}
Write-FeatureCommands

Write-Output ''
Write-Output ('Verification result: ' + $script:Passed.Count + ' checks passed, ' + $script:Failures.Count + ' checks failed.')
if ($script:Failures.Count -ne 0) {
    Write-Output ('Failed checks: ' + [string]::Join(', ', [string[]]$script:Failures))
    exit 1
}
exit 0
