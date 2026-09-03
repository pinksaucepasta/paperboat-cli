<#
  Paperboat's native Windows bootstrap. The only downloaded executable is the
  final pb.exe for this architecture. It is verified against current.json and
  then asks that same executable to perform the elevated installation.
#>
$ErrorActionPreference = 'Stop'

$server = if ($env:PAPERBOAT_SERVER) { [string]$env:PAPERBOAT_SERVER } else { 'https://api.pprbt.dev' }
$metadataUrl = if ($env:PAPERBOAT_RELEASE_METADATA_URL) { [string]$env:PAPERBOAT_RELEASE_METADATA_URL } else { "$server/current.json" }
$token = [string]$env:PAPERBOAT_ENROLLMENT_TOKEN
$name = [string]$env:PAPERBOAT_MACHINE_NAME
$freshEnrollment = -not [string]::IsNullOrWhiteSpace($token)
$requestedVersion = if ($env:PAPERBOAT_VERSION) { [string]$env:PAPERBOAT_VERSION } else { 'latest' }
$repo = if ($env:PAPERBOAT_GITHUB_REPOSITORY) { [string]$env:PAPERBOAT_GITHUB_REPOSITORY } else { 'pinksaucepasta/paperboat-cli' }

if ($server -notmatch '^https://') { throw 'Paperboat server URL must use HTTPS.' }
if ($metadataUrl -notmatch '^https://') { throw 'Paperboat release metadata URL must use HTTPS.' }
if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Paperboat release repository is invalid.' }
if ($freshEnrollment -and $token -notmatch '^[0-9A-Z]{26}$') { throw 'Paperboat enrollment token is invalid.' }

$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } elseif ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'X64') { 'amd64' } else { throw 'Paperboat supports only Windows AMD64 and ARM64.' }
$asset = "pb-windows-$arch.exe"
$current = (Invoke-WebRequest -UseBasicParsing -Uri $metadataUrl -TimeoutSec 30).Content | ConvertFrom-Json
$version = [string]$current.version
if ([string]$current.schema -ne 'paperboat.release-current/v1' -or $version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$' -or [string]$current.repository -ne $repo) {
  throw 'Paperboat current.json is invalid.'
}
if ($requestedVersion -ne 'latest' -and $requestedVersion -ne $version) { throw 'Requested Paperboat version is not the current release.' }

$assetProperty = $current.assets.PSObject.Properties[$asset]
if ($null -eq $assetProperty) { throw "Paperboat current.json has no metadata for $asset." }
$assetMetadata = $assetProperty.Value
if ([string]$assetMetadata.platform -ne 'windows' -or [string]$assetMetadata.architecture -ne $arch -or [string]$assetMetadata.format -ne 'pe' -or [string]$assetMetadata.sha256 -notmatch '^[0-9a-f]{64}$' -or [int64]$assetMetadata.length -lt 1) {
  throw "Paperboat current.json metadata for $asset is invalid."
}
$expectedUrl = "https://github.com/$repo/releases/download/$version/$asset"
if ([string]$assetMetadata.url -ne $expectedUrl) { throw 'Paperboat release asset URL is not an immutable GitHub release URL.' }

$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (-not [IO.Path]::IsPathRooted($tempRoot)) { throw 'Paperboat temporary directory must be absolute.' }
$dir = Join-Path $tempRoot ('Paperboat\bootstrap-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$download = Join-Path $dir $asset
$partial = "$download.download"
$installedPb = Join-Path ${env:ProgramFiles} 'Paperboat\bin\pb.exe'

function Download-ReleaseFile([string]$Url, [string]$Output) {
  for ($attempt = 1; $attempt -le 4; $attempt++) {
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
    try {
      $curl = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue
      if ($null -ne $curl) {
        & $curl.Source '--silent' '--show-error' '--location' '--fail' '--retry' '1' '--retry-all-errors' '--connect-timeout' '20' '--max-time' '300' '--output' $partial $Url
        if ($LASTEXITCODE -ne 0) { throw "curl exit $LASTEXITCODE" }
      } else {
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $partial -TimeoutSec 300 -MaximumRedirection 5
      }
      Move-Item -LiteralPath $partial -Destination $Output -Force
      return
    } catch {
      Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
      if ($attempt -eq 4) { throw "Download failed for $Url after $attempt attempts: $($_.Exception.Message)" }
      Start-Sleep -Seconds ($attempt * 2)
    }
  }
}

Download-ReleaseFile ([string]$assetMetadata.url) $download
$file = Get-Item -LiteralPath $download
if ([int64]$file.Length -ne [int64]$assetMetadata.length) { throw "Paperboat release asset length verification failed for $asset." }
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $download).Hash.ToLowerInvariant()
if ($actual -ne [string]$assetMetadata.sha256) { throw "Paperboat release asset digest verification failed for $asset." }

Unblock-File -LiteralPath $download -ErrorAction SilentlyContinue

$trustedBootstrapDirectory = Join-Path ${env:ProgramFiles} 'Paperboat\bootstrap'
function Stage-TrustedBootstrap([string]$Source) {
  New-Item -ItemType Directory -Force -Path $trustedBootstrapDirectory | Out-Null
  $staged = Join-Path $trustedBootstrapDirectory ('pb-' + [guid]::NewGuid().ToString('N') + '.exe')
  Copy-Item -LiteralPath $Source -Destination $staged -Force
  Unblock-File -LiteralPath $staged -ErrorAction SilentlyContinue
  return $staged
}

function Start-IsolatedInstallerProcess {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [Parameter(Mandatory = $true)]
    [object[]]$ArgumentList,
    [switch]$Elevated,
    [string]$StandardInputPath,
    [string]$StandardOutputPath,
    [string]$StandardErrorPath
  )
  if ([string]::IsNullOrWhiteSpace($FilePath)) { throw 'Installer process path is empty.' }
  $parameters = @{
    FilePath = $FilePath
    ArgumentList = $ArgumentList
    PassThru = $true
    WindowStyle = 'Hidden'
    ErrorAction = 'Stop'
  }
  if ($Elevated) {
    # ShellExecute's RunAs verb is the only supported way to show the normal
    # Windows consent/password dialog. ShellExecute owns the new process
    # handles, so it does not inherit the caller's anonymous pipes.
    $parameters.Verb = 'RunAs'
  } else {
    # CreateProcess inherits standard handles unless all three are redirected.
    # The empty input file gives a child deterministic EOF instead of the
    # installer's caller pipe, and the output files let us propagate diagnostics
    # after the child root has exited.
    if ([string]::IsNullOrWhiteSpace($StandardInputPath) -or
        [string]::IsNullOrWhiteSpace($StandardOutputPath) -or
        [string]::IsNullOrWhiteSpace($StandardErrorPath)) {
      throw 'Non-elevated installer processes require isolated standard handles.'
    }
    $parameters.RedirectStandardInput = $StandardInputPath
    $parameters.RedirectStandardOutput = $StandardOutputPath
    $parameters.RedirectStandardError = $StandardErrorPath
  }
  try {
    return Start-Process @parameters
  } catch {
    if ($Elevated) {
      throw "Installer process could not request administrator approval: $($_.Exception.Message)"
    }
    throw "Installer process could not start: $($_.Exception.Message)"
  }
}

function Stop-IsolatedInstallerProcess($Process) {
  if ($null -eq $Process) { return }
  try {
    if (-not $Process.HasExited) {
      # .NET 5+ supports the entireProcessTree overload. Windows PowerShell
      # falls back to the root process, which is still safe because every
      # standard handle is redirected and no caller pipe can remain open.
      try { $Process.Kill($true) } catch { $Process.Kill() }
    }
  } catch { }
}

function Wait-InstallerProcess($Process, [string]$Operation) {
  if ($null -eq $Process) { throw "$Operation did not return a process handle." }
  # Never use Start-Process -Wait: it can wait for a detached descendant tree.
  # WaitForExit waits this process root only, and the caller's pipe handles were
  # excluded by Start-IsolatedInstallerProcess.
  if (-not $Process.WaitForExit(1200000)) {
    Stop-IsolatedInstallerProcess $Process
    if (-not $Process.WaitForExit(5000)) {
      throw "$Operation exceeded the 20 minute limit and could not be stopped."
    }
    throw "$Operation exceeded the 20 minute limit."
  }
  return [int]$Process.ExitCode
}

function Assert-InstalledVersion([string]$Path, [string]$ExpectedVersion) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  $capture = [IO.Path]::GetTempFileName()
  $captureError = "$capture.err"
  $captureInput = "$capture.in"
  New-Item -ItemType File -Path $captureInput -Force | Out-Null
  try {
    $probe = Start-IsolatedInstallerProcess -FilePath $Path -ArgumentList @('--version') -StandardInputPath $captureInput -StandardOutputPath $capture -StandardErrorPath $captureError
    $probeExitCode = Wait-InstallerProcess $probe 'Paperboat version probe'
    if ($probeExitCode -ne 0) { return $false }
    $output = ((Get-Content -LiteralPath $capture -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $captureError -Raw -ErrorAction SilentlyContinue))
  } catch {
    return $false
  } finally {
    Remove-Item -LiteralPath $capture,$captureError,$captureInput -Force -ErrorAction SilentlyContinue
  }
  $versionMatches = [regex]::Matches($output, '(Version[\t ]+[0-9A-Za-z._-]+)')
  return $versionMatches.Count -eq 1 -and $versionMatches[0].Groups[1].Value -eq ("Version " + $ExpectedVersion)
}

if (-not (Assert-InstalledVersion $download $version)) {
  throw "Downloaded Paperboat release does not report version $version."
}

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-InteractiveUac {
  # A UAC broker needs a desktop that can display and receive the consent
  # prompt. OpenSSH and service/CI sessions are deliberately rejected here so
  # an unattended install fails immediately instead of waiting forever on a
  # prompt nobody can answer.
  if (-not [System.Environment]::UserInteractive) { return $false }
  if (-not [string]::IsNullOrWhiteSpace([string]$env:SSH_CONNECTION) -or
      -not [string]::IsNullOrWhiteSpace([string]$env:SSH_CLIENT) -or
      -not [string]::IsNullOrWhiteSpace([string]$env:SSH_TTY)) {
    return $false
  }
  try {
    return (Get-Process -Id $PID -ErrorAction Stop).SessionId -ne 0
  } catch {
    return $false
  }
}

function Read-ProcessCapture([string]$StandardOutputPath, [string]$StandardErrorPath) {
  $parts = @()
  foreach ($path in @($StandardOutputPath, $StandardErrorPath)) {
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
      $part = [string](Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue)
      if ($part.Length -gt 1048576) { $part = $part.Substring(0, 1048576) }
      if ($part.Length -gt 0) { $parts += $part }
    }
  }
  $text = [string]::Join('', [string[]]$parts)
  if ($text.Length -gt 2000) { return $text.Substring(0, 2000) }
  return $text
}

function Publish-ProcessCapture([string]$StandardOutputPath, [string]$StandardErrorPath) {
  if (-not [string]::IsNullOrWhiteSpace($StandardOutputPath) -and (Test-Path -LiteralPath $StandardOutputPath -PathType Leaf)) {
    $stdout = [string](Get-Content -LiteralPath $StandardOutputPath -Raw -ErrorAction SilentlyContinue)
    if ($stdout.Length -gt 1048576) { $stdout = $stdout.Substring(0, 1048576) }
    if ($stdout.Length -gt 0) { [Console]::Out.Write($stdout) }
  }
  if (-not [string]::IsNullOrWhiteSpace($StandardErrorPath) -and (Test-Path -LiteralPath $StandardErrorPath -PathType Leaf)) {
    $stderr = [string](Get-Content -LiteralPath $StandardErrorPath -Raw -ErrorAction SilentlyContinue)
    if ($stderr.Length -gt 1048576) { $stderr = $stderr.Substring(0, 1048576) }
    if ($stderr.Length -gt 0) { [Console]::Error.Write($stderr) }
  }
}

function Test-RegularNonReparseFile([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { return $false }
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return (-not $item.PSIsContainer) -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
  } catch {
    return $false
  }
}

function New-EnrollmentTokenFile([string]$Token) {
  if ([string]::IsNullOrWhiteSpace($Token)) { throw 'Paperboat enrollment token is empty.' }
  $path = Join-Path $dir ('enrollment-token-' + [guid]::NewGuid().ToString('N') + '.txt')
  if (-not [IO.Path]::IsPathRooted($path)) { throw 'Paperboat enrollment token file path must be absolute.' }
  $stream = $null
  try {
    # CreateNew prevents an attacker from replacing a predictable path with a
    # reparse point before the token is written.
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $bytes = [Text.Encoding]::ASCII.GetBytes($Token)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
  } catch {
    if ($null -ne $stream) { $stream.Dispose() }
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    throw "Could not create the protected Paperboat enrollment token file: $($_.Exception.Message)"
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
  }
  if (-not (Test-RegularNonReparseFile $path)) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    throw 'Paperboat enrollment token file is not a regular non-reparse file.'
  }

  try {
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([string]::IsNullOrWhiteSpace($userSid)) { throw 'current Windows user SID is unavailable' }
    $security = New-Object System.Security.AccessControl.FileSecurity
    $sddl = 'O:' + $userSid + 'D:P(A;;FA;;;SY)(A;;FA;;;' + $userSid + ')'
    $security.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop
  } catch {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    throw "Could not protect the Paperboat enrollment token file: $($_.Exception.Message)"
  }
  if (-not (Test-RegularNonReparseFile $path)) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    throw 'Paperboat enrollment token file became unsafe before pairing.'
  }
  return $path
}

function Remove-EnrollmentTokenFile([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  try {
    if (Test-Path -LiteralPath $Path) {
      Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $Path) { throw 'token file remains after cleanup' }
  } catch {
    throw "Could not remove the Paperboat enrollment token file: $($_.Exception.Message)"
  }
}

function Assert-InstalledRelease([string]$Path, [string]$ExpectedVersion, [string]$ExpectedHash) {
  if (-not (Assert-InstalledVersion $Path $ExpectedVersion)) { return $false }
  try {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLowerInvariant()
    return $hash -eq $ExpectedHash
  } catch {
    return $false
  }
}

function Invoke-FreshPairRollback {
  # The pair command runs in the original user's process, after __install has
  # crossed the machine replacement boundary. Roll back both scopes when that
  # final step fails. The elevated payload derives fixed Paperboat paths; it
  # never accepts a caller-provided deletion root.
  $rollbackError = $null
  foreach ($statePath in @(
    (Join-Path $env:LOCALAPPDATA 'Paperboat'),
    (Join-Path $env:APPDATA 'Paperboat')
  )) {
    try {
      if (Test-Path -LiteralPath $statePath) {
        Remove-Item -LiteralPath $statePath -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $statePath) { throw "user state remains after rollback: $statePath" }
      }
    } catch {
      if ($null -eq $rollbackError) { $rollbackError = $_ }
    }
  }
  $rollbackPayload = @'
$ErrorActionPreference = 'Stop'
$programRoot = Join-Path ${env:ProgramFiles} 'Paperboat'
$installed = Join-Path $programRoot 'bin\pb.exe'
$purgeError = $null
function Wait-RollbackProcess($Process, [string]$Operation) {
  if ($null -eq $Process) { throw "$Operation did not return a process handle." }
  if (-not $Process.WaitForExit(1200000)) {
    try { $Process.Kill() } catch { }
    if (-not $Process.WaitForExit(5000)) {
      throw "$Operation exceeded the 20 minute limit and could not be stopped."
    }
    throw "$Operation exceeded the 20 minute limit."
  }
  return [int]$Process.ExitCode
}
try {
  if (Test-Path -LiteralPath $installed -PathType Leaf) {
    $purge = Start-Process -FilePath $installed -ArgumentList @('__runtime-service', 'purge') -PassThru -WindowStyle Hidden
    $purgeExitCode = Wait-RollbackProcess $purge 'Paperboat runtime purge'
    if ($purgeExitCode -ne 0) { throw "Paperboat runtime purge failed with exit code $purgeExitCode." }
  }
} catch {
  $purgeError = $_
}
try {
  # __install --fresh owns this exact root. Remove the payload only after the
  # executable has exited, so the rollback is safe on Windows file locking.
  Remove-Item -LiteralPath $programRoot -Recurse -Force -ErrorAction Stop
  if (Test-Path -LiteralPath $programRoot) {
    throw "Paperboat fresh-install payload remains after rollback."
  }
} catch {
  if ($null -eq $purgeError) { $purgeError = $_ }
}
if ($null -ne $purgeError) { throw $purgeError }
'@
  $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rollbackPayload))
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  try {
    $rollbackArguments = @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedPayload)
    if (Test-Administrator) {
      $rollbackInput = Join-Path $dir 'rollback.stdin'
      $rollbackOutput = Join-Path $dir 'rollback.stdout'
      $rollbackError = Join-Path $dir 'rollback.stderr'
      New-Item -ItemType File -Path $rollbackInput -Force | Out-Null
      $rollback = Start-IsolatedInstallerProcess -FilePath $powershell -ArgumentList $rollbackArguments -StandardInputPath $rollbackInput -StandardOutputPath $rollbackOutput -StandardErrorPath $rollbackError
    } elseif (-not (Test-InteractiveUac)) {
      throw 'Paperboat fresh-install rollback requires an elevated administrator PowerShell session when no interactive UAC desktop is available.'
    } else {
      # RunAs is intentionally kept on the interactive branch so Windows can
      # display its normal consent/password prompt. The process root is still
      # waited explicitly, never with Start-Process -Wait.
      $rollback = Start-IsolatedInstallerProcess -FilePath $powershell -ArgumentList $rollbackArguments -Elevated
    }
    $rollbackExitCode = Wait-InstallerProcess $rollback 'Paperboat fresh-install rollback'
    if ($rollbackExitCode -ne 0) { throw "rollback exited with code $rollbackExitCode" }
  } catch {
    if ($null -eq $rollbackError) { $rollbackError = $_ }
  }
  if ($null -ne $rollbackError) { throw $rollbackError }
}

if ($freshEnrollment -or -not (Assert-InstalledRelease $installedPb $version $actual)) {
  # __install is implemented by the downloaded pb.exe itself. This is the
  # only binary-install elevation boundary and avoids downloading another
  # executable.
  $arguments = @('__install', '--source', $download, '--version', $version)
  if ($freshEnrollment) { $arguments += '--fresh' }
  $administrator = Test-Administrator
  if (-not $administrator -and -not (Test-InteractiveUac)) {
    throw 'Paperboat installation requires administrator privileges. Run PowerShell as Administrator for unattended or SSH execution, or rerun this command from an interactive desktop to approve the UAC prompt.'
  }
  $installerExecutable = $null
  try { $installerExecutable = Stage-TrustedBootstrap $download } catch { $installerExecutable = $null }
  if ($null -ne $installerExecutable) {
    $arguments[2] = $installerExecutable
  }
  $runAsPath = if ($null -ne $installerExecutable) { $installerExecutable } else { $download }
  $processArguments = @($arguments)
  if ([string]$processArguments[2] -match '\s') { $processArguments[2] = '"' + $processArguments[2] + '"' }
  $installInput = Join-Path $dir 'install.stdin'
  $installOutput = Join-Path $dir 'install.stdout'
  $installError = Join-Path $dir 'install.stderr'
  New-Item -ItemType File -Path $installInput -Force | Out-Null
  if ($administrator) {
    # An administrator token does not need UAC. Start a separate process anyway
    # so the downloaded executable cannot inherit the caller's SSH/pipe handles.
    $process = Start-IsolatedInstallerProcess -FilePath $runAsPath -ArgumentList $processArguments -StandardInputPath $installInput -StandardOutputPath $installOutput -StandardErrorPath $installError
  } else {
    # RunAs preserves the visible UAC/password experience. ShellExecute starts
    # the elevated root outside the caller's anonymous pipe handles.
    $process = Start-IsolatedInstallerProcess -FilePath $runAsPath -ArgumentList $processArguments -Elevated
  }
  $installExitCode = Wait-InstallerProcess $process 'Paperboat self-install'
  Publish-ProcessCapture $installOutput $installError
  if ($installExitCode -ne 0) {
    $detail = Read-ProcessCapture $installOutput $installError
    if ([string]::IsNullOrWhiteSpace($detail)) { throw "Paperboat self-install failed with exit code $installExitCode." }
    throw "Paperboat self-install failed with exit code $($installExitCode): $detail"
  }
}
if (-not (Assert-InstalledRelease $installedPb $version $actual)) { throw "Installed Paperboat does not match verified release $version." }

# The trusted bootstrap is needed only across the elevation boundary. Never
# accumulate verified staging copies after the installed digest is proven.
if ($null -ne $installerExecutable) {
  Remove-Item -LiteralPath $installerExecutable -Force -ErrorAction SilentlyContinue
}

if ($freshEnrollment) {
  # Only cross the replacement boundary after the verified elevated install
  # has succeeded. If UAC is denied or the elevated process cannot start,
  # the existing enrollment remains intact and the token can be retried.
  # __install --fresh already removes machine-wide services and state.
  foreach ($statePath in @(
    (Join-Path $env:LOCALAPPDATA 'Paperboat'),
    (Join-Path $env:APPDATA 'Paperboat')
  )) {
    if (Test-Path -LiteralPath $statePath) {
      Remove-Item -LiteralPath $statePath -Recurse -Force -ErrorAction Stop
      if (Test-Path -LiteralPath $statePath) { throw "Paperboat user state remains after fresh cleanup: $statePath" }
    }
  }
  if ([string]::IsNullOrWhiteSpace($name)) {
    $name = [string]$env:COMPUTERNAME
  }
  $name = $name.Trim().ToLowerInvariant()
  $first = $token.Substring(0, 1)
  $setupMode = if ('02468BDFHJLNPRTVXZ'.Contains($first)) { 'host' } else { 'client' }
  Remove-Item Env:PAPERBOAT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
  # Pair in the original user's security context, but use an isolated child so
  # the dashboard shell's stdin/stdout/stderr pipes cannot keep the installer
  # alive after pairing completes. No elevation is used for this user-owned
  # profile/DPAPI operation.
  $pairFailed = $false
  $tokenFile = $null
  $tokenCleanupError = $null
  try {
    $tokenFile = New-EnrollmentTokenFile $token
    $pairArguments = @('pair', '--server', $server, '--enrollment-token-file', $tokenFile, '--name', $name, "--setup-mode=$setupMode")
    if ([string]$pairArguments[4] -match '\s') { $pairArguments[4] = '"' + $pairArguments[4] + '"' }
    if ([string]$pairArguments[6] -match '\s') { $pairArguments[6] = '"' + $pairArguments[6] + '"' }
    $pairInput = Join-Path $dir 'pair.stdin'
    $pairOutput = Join-Path $dir 'pair.stdout'
    $pairError = Join-Path $dir 'pair.stderr'
    New-Item -ItemType File -Path $pairInput -Force | Out-Null
    $pairProcess = Start-IsolatedInstallerProcess -FilePath $installedPb -ArgumentList $pairArguments -StandardInputPath $pairInput -StandardOutputPath $pairOutput -StandardErrorPath $pairError
    $pairExitCode = Wait-InstallerProcess $pairProcess 'Paperboat pairing'
    Publish-ProcessCapture $pairOutput $pairError
    if ($pairExitCode -ne 0) {
      $pairFailed = $true
      Write-Warning "Paperboat pairing failed with exit code $pairExitCode; rolling back the fresh installation."
      try {
        Invoke-FreshPairRollback
      } catch {
        # Preserve the pair failure as the primary result, but make an
        # incomplete rollback visible so support can safely retry cleanup.
        Write-Warning "Paperboat fresh-install rollback did not complete: $($_.Exception.Message)"
      }
    }
  } finally {
    if ($null -ne $tokenFile) {
      try {
        Remove-EnrollmentTokenFile $tokenFile
      } catch {
        $tokenCleanupError = $_
        Write-Warning "Paperboat enrollment token cleanup did not complete: $($_.Exception.Message)"
      }
    }
    $token = $null
  }
  if ($pairFailed) {
    exit $pairExitCode
  }
  if ($null -ne $tokenCleanupError) {
    throw $tokenCleanupError
  }
}
