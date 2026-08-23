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

    [Parameter(Mandatory = $true)]
    [string] $S4UFixturePath,

    [Parameter(Mandatory = $true)]
    [string] $S4UTestExecutable,

    [Parameter(Mandatory = $true)]
    [string] $HostinstallTestExecutable,

    [Parameter(Mandatory = $true)]
    [string] $MsiCleanupTestExecutable,

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
$script:dynamicPreviewDescriptorPath = $null
$script:runtimeCurrentFixtureCreated = $false
$script:preMsiRuntimeCurrentFixtureCreated = $false
$script:preMsiRuntimeCurrentPath = $null
$script:preMsiRuntimeCurrentRoot = $null
$script:preMsiRuntimeCurrentReleasesRoot = $null
$script:preMsiRuntimeCurrentHash = $null
$script:preMsiRuntimeCurrentStaged = $false
$script:qualificationSID = $null
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
$resolvedS4UFixturePath = [IO.Path]::GetFullPath($S4UFixturePath)
$resolvedS4UTestExecutable = [IO.Path]::GetFullPath($S4UTestExecutable)
$resolvedHostinstallTestExecutable = [IO.Path]::GetFullPath($HostinstallTestExecutable)
$resolvedMsiCleanupTestExecutable = [IO.Path]::GetFullPath($MsiCleanupTestExecutable)
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

function Assert-QualificationRegularFile {
    param([Parameter(Mandatory = $true)][string] $Path)
    Assert-Qualification (Test-Path -LiteralPath $Path -PathType Leaf) "Qualification file is missing: $Path"
    $item = Get-Item -Force -LiteralPath $Path
    Assert-Qualification (-not $item.PSIsContainer) "Qualification file is a directory: $Path"
    Assert-Qualification ((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Qualification file is a reparse point: $Path"
}

function Assert-InstalledMachineACL {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][bool] $Directory
    )
    Assert-Qualification (Test-Path -LiteralPath $Path) "Installed ACL target is missing: $Path"
    $item = Get-Item -Force -LiteralPath $Path
    Assert-Qualification ((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Installed ACL target is a reparse point: $Path"
    Assert-Qualification ($Directory -eq $item.PSIsContainer) "Installed ACL target type is wrong: $Path"
    $acl = Get-Acl -LiteralPath $Path
    $systemSID = 'S-1-5-18'
    $administratorsSID = 'S-1-5-32-544'
    $usersSID = 'S-1-5-32-545'
    $ownerSID = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Assert-Qualification ($ownerSID -eq $systemSID) "Installed ACL owner is $ownerSID, expected LocalSystem: $Path"
    Assert-Qualification ($acl.AreAccessRulesProtected) "Installed ACL inherits mutable parent permissions: $Path"
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    Assert-Qualification ($rules.Count -eq 3) "Installed ACL has $($rules.Count) explicit rules, expected 3: $Path"
    $expectedInheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [Security.AccessControl.InheritanceFlags]::ContainerInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($expected in @(
        @{ SID = $systemSID; Rights = [int64][Security.AccessControl.FileSystemRights]::FullControl },
        @{ SID = $administratorsSID; Rights = [int64][Security.AccessControl.FileSystemRights]::FullControl },
        @{ SID = $usersSID; Rights = [int64]0x1200a9 }
    )) {
        $matching = @($rules | Where-Object { $_.IdentityReference.Value -eq $expected.SID })
        Assert-Qualification ($matching.Count -eq 1) "Installed ACL does not contain exactly one rule for $($expected.SID): $Path"
        $rule = $matching[0]
        Assert-Qualification ([int64]$rule.FileSystemRights -eq $expected.Rights) "Installed ACL rights for $($expected.SID) are $($rule.FileSystemRights): $Path"
        Assert-Qualification ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) "Installed ACL denies expected principal $($expected.SID): $Path"
        Assert-Qualification ($rule.InheritanceFlags -eq $expectedInheritance) "Installed ACL inheritance flags for $($expected.SID) are $($rule.InheritanceFlags): $Path"
        Assert-Qualification ($rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None) "Installed ACL propagation flags for $($expected.SID) are $($rule.PropagationFlags): $Path"
    }
}

function Set-QualificationRuntimeCurrentACL {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][bool] $Directory,
        [Parameter(Mandatory = $true)][string] $QualificationSID
    )
    Assert-Qualification (Test-Path -LiteralPath $Path) "Runtime-current ACL target is missing: $Path"
    $item = Get-Item -Force -LiteralPath $Path
    Assert-Qualification ($Directory -eq $item.PSIsContainer) "Runtime-current ACL target type is wrong: $Path"
    $variableNames = @(
        'PAPERBOAT_WINDOWS_E2E_ACL_PATH',
        'PAPERBOAT_WINDOWS_E2E_ACL_DIRECTORY',
        'PAPERBOAT_WINDOWS_E2E_ACL_SID'
    )
    $previous = @{}
    foreach ($variableName in $variableNames) {
        $previous[$variableName] = [Environment]::GetEnvironmentVariable($variableName, 'Process')
    }
    try {
        $directoryValue = if ($Directory) { '1' } else { '0' }
        [Environment]::SetEnvironmentVariable('PAPERBOAT_WINDOWS_E2E_ACL_PATH', $Path, 'Process')
        [Environment]::SetEnvironmentVariable('PAPERBOAT_WINDOWS_E2E_ACL_DIRECTORY', $directoryValue, 'Process')
        [Environment]::SetEnvironmentVariable('PAPERBOAT_WINDOWS_E2E_ACL_SID', $QualificationSID, 'Process')
        $arguments = @('-test.v', '-test.run', '^TestNativeApplyQualificationRuntimeCurrentACL$', '-test.count', '1', '-test.timeout', '1m')
        & $resolvedHostinstallTestExecutable @arguments
        $exitCode = $LASTEXITCODE
        Assert-Qualification ($exitCode -eq 0) "Native runtime-current ACL helper failed with exit code $exitCode."
    }
    finally {
        foreach ($variableName in $variableNames) {
            [Environment]::SetEnvironmentVariable($variableName, $previous[$variableName], 'Process')
        }
    }
}

function Assert-QualificationRuntimeCurrentACL {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][bool] $Directory,
        [Parameter(Mandatory = $true)][string] $QualificationSID
    )
    Assert-Qualification (Test-Path -LiteralPath $Path) "Runtime-current ACL target is missing: $Path"
    $item = Get-Item -Force -LiteralPath $Path
    Assert-Qualification ((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Runtime-current ACL target is a reparse point: $Path"
    Assert-Qualification ($Directory -eq $item.PSIsContainer) "Runtime-current ACL target type is wrong: $Path"
    $acl = Get-Acl -LiteralPath $Path
    $systemSID = 'S-1-5-18'
    $administratorsSID = 'S-1-5-32-544'
    Assert-Qualification ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $systemSID) "Runtime-current ACL owner is not LocalSystem: $Path"
    Assert-Qualification ($acl.AreAccessRulesProtected) "Runtime-current ACL inherits mutable parent permissions: $Path"
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    Assert-Qualification ($rules.Count -eq 3) "Runtime-current ACL has $($rules.Count) explicit rules, expected 3: $Path"
    $expectedInheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [Security.AccessControl.InheritanceFlags]::ContainerInherit
    }
    else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($expected in @(
        @{ SID = $systemSID; Rights = [int64][Security.AccessControl.FileSystemRights]::FullControl },
        @{ SID = $administratorsSID; Rights = [int64][Security.AccessControl.FileSystemRights]::FullControl },
        @{ SID = $QualificationSID; Rights = [int64]0x1200a9 }
    )) {
        $matching = @($rules | Where-Object { $_.IdentityReference.Value -eq $expected.SID })
        Assert-Qualification ($matching.Count -eq 1) "Runtime-current ACL does not contain exactly one rule for $($expected.SID): $Path"
        $rule = $matching[0]
        Assert-Qualification ([int64]$rule.FileSystemRights -eq $expected.Rights) "Runtime-current ACL rights for $($expected.SID) are $($rule.FileSystemRights): $Path"
        Assert-Qualification ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) "Runtime-current ACL denies expected principal $($expected.SID): $Path"
        Assert-Qualification ($rule.InheritanceFlags -eq $expectedInheritance) "Runtime-current ACL inheritance flags for $($expected.SID) are $($rule.InheritanceFlags): $Path"
        Assert-Qualification ($rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None) "Runtime-current ACL propagation flags for $($expected.SID) are $($rule.PropagationFlags): $Path"
    }
}

function Get-QualificationTrustedSIDs {
    $trustedInstaller = ([Security.Principal.NTAccount]::new('NT SERVICE', 'TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
    return @('S-1-5-18', 'S-1-5-32-544', $trustedInstaller)
}

function Get-QualificationSID {
    param([Parameter(Mandatory = $true)] $Identity)
    if ($Identity -is [string]) {
        $Identity = [Security.Principal.NTAccount]::new($Identity)
    }
    return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-QualificationAncestorTrusted {
    param([Parameter(Mandatory = $true)][string] $Path)
    Assert-Qualification (Test-Path -LiteralPath $Path -PathType Container) "Qualification ancestor is missing: $Path"
    Assert-Qualification (((Get-Item -Force -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "Qualification ancestor is a reparse point: $Path"
    $acl = Get-Acl -LiteralPath $Path
    $trustedSIDs = @(Get-QualificationTrustedSIDs)
    $ownerSID = Get-QualificationSID $acl.Owner
    Assert-Qualification ($ownerSID -in $trustedSIDs) "Qualification ancestor has an untrusted owner: $Path owner=$ownerSID"
    $dangerousRights = [int64]([Security.AccessControl.FileSystemRights]::Delete) -bor [int64]([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -bor [int64]([Security.AccessControl.FileSystemRights]::ChangePermissions) -bor [int64]([Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
            continue
        }
        $ruleSID = Get-QualificationSID $rule.IdentityReference
        if ($ruleSID -notin $trustedSIDs -and (([int64]$rule.FileSystemRights -band $dangerousRights) -ne 0)) {
            throw "qualification_assertion_failed: Qualification ancestor grants an untrusted principal delete-child or ACL ownership rights: $Path sid=$ruleSID rights=$($rule.FileSystemRights)"
        }
    }
}

function New-QualificationRootSecurity {
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($administrators)
    $security.SetAccessRuleProtection($true, $false)
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    return $security
}

function Assert-QualificationTrustedRoot {
    param([Parameter(Mandatory = $true)][string] $Path)
    Assert-QualificationAncestorTrusted $Path
    $actual = Get-Acl -LiteralPath $Path
    Assert-Qualification ($actual.AreAccessRulesProtected) "Qualification root DACL is not protected: $Path"
    $trustedRuleSeen = @{}
    foreach ($rule in $actual.Access) {
        $ruleSID = Get-QualificationSID $rule.IdentityReference
        Assert-Qualification ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $ruleSID -in @('S-1-5-18', 'S-1-5-32-544')) "Qualification root contains an unexpected ACE: $Path sid=$ruleSID"
        Assert-Qualification ($rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl) "Qualification root trusted ACE is not FullControl: $Path sid=$ruleSID rights=$($rule.FileSystemRights)"
        $trustedRuleSeen[$ruleSID] = $true
    }
    Assert-Qualification ($trustedRuleSeen['S-1-5-18'] -and $trustedRuleSeen['S-1-5-32-544']) "Qualification root is missing the required System or Administrators ACE: $Path"
}

function New-QualificationTrustedRootAtomic {
    param([Parameter(Mandatory = $true)][string] $Path)
    Assert-Qualification (-not (Test-Path -LiteralPath $Path)) "Refusing to mutate an existing qualification root: $Path"
    $security = New-QualificationRootSecurity
    [IO.Directory]::CreateDirectory($Path, $security) | Out-Null
    Assert-QualificationTrustedRoot $Path
}

function Assert-QualificationTransactionDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $OwnerSID,
        [Parameter(Mandatory = $true)][bool] $OwnerWritable
    )
    Assert-Qualification (Test-Path -LiteralPath $Path -PathType Container) "Qualification transaction directory is missing: $Path"
    Assert-Qualification (((Get-Item -Force -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "Qualification transaction directory is a reparse point: $Path"
    $acl = Get-Acl -LiteralPath $Path
    $trustedSIDs = @('S-1-5-18', 'S-1-5-32-544')
    Assert-Qualification ((Get-QualificationSID $acl.Owner) -in $trustedSIDs) "Qualification transaction directory has an untrusted filesystem owner: $Path"
    Assert-Qualification ($acl.AreAccessRulesProtected) "Qualification transaction directory DACL is not protected: $Path"
    $ownerRuleSeen = $false
    $trustedRuleSeen = @{}
    $writeRights = [int64]([Security.AccessControl.FileSystemRights]::Write) -bor [int64]([Security.AccessControl.FileSystemRights]::Delete) -bor [int64]([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -bor [int64]([Security.AccessControl.FileSystemRights]::ChangePermissions) -bor [int64]([Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($rule in $acl.Access) {
        $ruleSID = Get-QualificationSID $rule.IdentityReference
        Assert-Qualification ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($ruleSID -in $trustedSIDs -or $ruleSID -eq $OwnerSID)) "Qualification transaction directory contains an unexpected ACE: $Path sid=$ruleSID"
        if ($ruleSID -eq $OwnerSID) {
            $ownerRuleSeen = $true
            $ownerCanWrite = (([int64]$rule.FileSystemRights -band $writeRights) -ne 0)
            Assert-Qualification ($ownerCanWrite -eq $OwnerWritable) "Qualification owner permissions do not match the directory role: $Path rights=$($rule.FileSystemRights)"
        }
        elseif ($ruleSID -in $trustedSIDs) {
            Assert-Qualification ($rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl) "Qualification trusted ACE is not FullControl: $Path sid=$ruleSID rights=$($rule.FileSystemRights)"
            $trustedRuleSeen[$ruleSID] = $true
        }
    }
    Assert-Qualification ($ownerRuleSeen) "Qualification transaction directory is missing the enrolled-owner ACE: $Path"
    Assert-Qualification ($trustedRuleSeen['S-1-5-18'] -and $trustedRuleSeen['S-1-5-32-544']) "Qualification transaction directory is missing the required System or Administrators ACE: $Path"
}

function Test-QualificationTrustValidation {
    param([Parameter(Mandatory = $true)][string] $UntrustedSID)
    $fixtureBase = Join-Path $resolvedOutputDirectory ('qualification-trust-' + [Guid]::NewGuid().ToString('N'))
    $foreignOwnerPath = Join-Path $fixtureBase 'foreign-owner'
    $deleteACEPath = Join-Path $fixtureBase 'delete-ace'
    $inheritOnlyPath = Join-Path $fixtureBase 'inherit-only-ace'
    $reparsePath = Join-Path $fixtureBase 'reparse-owner'
    try {
        New-Item -ItemType Directory -Force -Path $foreignOwnerPath | Out-Null
        & icacls.exe $foreignOwnerPath /setowner "*$UntrustedSID" | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not create the hostile-owner qualification fixture.'
        $foreignOwnerRejected = $false
        try {
            Assert-QualificationAncestorTrusted $foreignOwnerPath
        }
        catch {
            $foreignOwnerRejected = $true
        }
        Assert-Qualification $foreignOwnerRejected 'Qualification trust validation accepted a foreign-owned ancestor.'
        $foreignCreationRejected = $false
        try {
            New-QualificationTrustedRootAtomic $foreignOwnerPath
        }
        catch {
            $foreignCreationRejected = $true
        }
        Assert-Qualification $foreignCreationRejected 'Atomic qualification root creation accepted an existing foreign-owned path.'
        $foreignOwnerACL = Get-Acl -LiteralPath $foreignOwnerPath
        $foreignOwnerAfter = Get-QualificationSID $foreignOwnerACL.Owner
        Assert-Qualification ($foreignOwnerAfter -eq $UntrustedSID) 'Atomic qualification root creation mutated the foreign-owned path.'

        New-QualificationTrustedRootAtomic $deleteACEPath
        & icacls.exe $deleteACEPath /grant "*${UntrustedSID}:D" | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not create the hostile delete-ACE qualification fixture.'
        $deleteACERejected = $false
        try {
            Assert-QualificationAncestorTrusted $deleteACEPath
        }
        catch {
            $deleteACERejected = $true
        }
        Assert-Qualification $deleteACERejected 'Qualification trust validation accepted an untrusted Delete ACE.'

        New-QualificationTrustedRootAtomic $inheritOnlyPath
        $inheritOnlyACL = Get-Acl -LiteralPath $inheritOnlyPath
        $untrustedIdentity = [Security.Principal.SecurityIdentifier]::new($UntrustedSID)
        $inheritOnlyACL.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($untrustedIdentity, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit, [Security.AccessControl.PropagationFlags]::InheritOnly, [Security.AccessControl.AccessControlType]::Allow))
        Set-Acl -LiteralPath $inheritOnlyPath -AclObject $inheritOnlyACL
        Assert-QualificationAncestorTrusted $inheritOnlyPath

        New-Item -ItemType Junction -Path $reparsePath -Target $foreignOwnerPath | Out-Null
        $reparseRejected = $false
        try {
            Assert-QualificationAncestorTrusted $reparsePath
        }
        catch {
            $reparseRejected = $true
        }
        Assert-Qualification $reparseRejected 'Qualification trust validation accepted a reparse ancestor.'
    }
    finally {
        if (Test-Path -LiteralPath $fixtureBase) {
            Remove-Item -LiteralPath $fixtureBase -Recurse -Force -ErrorAction Stop
            Assert-Qualification (-not (Test-Path -LiteralPath $fixtureBase)) 'Qualification trust-validation fixture remains after cleanup.'
        }
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
    @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {
        $_.Name -in @('PaperboatHostd', 'PaperboatUpdated')
    })
}

function Get-PaperboatPreviewServices {
    @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {
        $_.Name -like 'PaperboatPreview-*'
    })
}

function Get-PaperboatPreviewDeclarations {
    $definitionRoot = Join-Path $script:stateRoot 'services'
    if (-not (Test-Path -LiteralPath $definitionRoot)) {
        return @()
    }
    return @(Get-ChildItem -Force -File -LiteralPath $definitionRoot -Filter 'PaperboatPreview-*.json' -ErrorAction Stop)
}

function Get-InstalledPaperboatProducts {
    $entries = @()
    foreach ($root in @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )) {
        if (Test-Path -LiteralPath $root) {
            $entries += @(Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
                $item = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
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
    Assert-Qualification (Test-Path -LiteralPath $resolvedS4UFixturePath -PathType Leaf) "Windows S4U fixture is missing: $resolvedS4UFixturePath"
    Assert-Qualification ([IO.Path]::GetExtension($resolvedS4UFixturePath) -ieq '.exe') "Windows S4U fixture must be an .exe."
    Assert-Qualification (Test-Path -LiteralPath $resolvedS4UTestExecutable -PathType Leaf) "Windows S4U test executable is missing: $resolvedS4UTestExecutable"
    Assert-Qualification ([IO.Path]::GetExtension($resolvedS4UTestExecutable) -ieq '.exe') "Windows S4U test executable must be an .exe."
    Assert-Qualification (Test-Path -LiteralPath $resolvedHostinstallTestExecutable -PathType Leaf) "Windows host-install qualification test executable is missing: $resolvedHostinstallTestExecutable"
    Assert-Qualification ([IO.Path]::GetExtension($resolvedHostinstallTestExecutable) -ieq '.exe') "Windows host-install qualification test executable must be an .exe."
    Assert-Qualification (Test-Path -LiteralPath $resolvedMsiCleanupTestExecutable -PathType Leaf) "Windows MSI cleanup qualification test executable is missing: $resolvedMsiCleanupTestExecutable"
    Assert-Qualification ([IO.Path]::GetExtension($resolvedMsiCleanupTestExecutable) -ieq '.exe') "Windows MSI cleanup qualification test executable must be an .exe."
    Assert-Qualification ([Environment]::Is64BitOperatingSystem) 'Qualification requires a 64-bit Windows operating system.'
    $nativeArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $expectedArchitecture = if ($Architecture -eq 'amd64') { 'X64' } else { 'Arm64' }
    Assert-Qualification ($nativeArchitecture -eq $expectedArchitecture) "Requested $Architecture qualification on native architecture $nativeArchitecture."
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-Qualification ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Qualification must run with administrator rights.'
    $script:qualificationSID = Get-QualificationSID $identity.User
    Assert-Qualification (-not [string]::IsNullOrWhiteSpace($script:qualificationSID)) 'Qualification identity has no SID for runtime-current ACL validation.'
    Assert-Qualification ($script:qualificationSID -notin @('S-1-5-18', 'S-1-5-32-544')) 'Qualification identity must be a non-trusted user SID for runtime-current ACL validation.'
    Assert-Qualification (@(Get-PaperboatServices).Count -eq 0) 'PaperboatHostd or PaperboatUpdated already exists; refusing to overwrite an unmanaged test state.'
    Assert-Qualification (@(Get-PaperboatPreviewServices).Count -eq 0) 'A PaperboatPreview-* service already exists; refusing to overwrite an unmanaged test state.'
    Assert-Qualification (@(Get-PaperboatPreviewDeclarations).Count -eq 0) 'A PaperboatPreview-* service declaration already exists; refusing to overwrite an unmanaged test state.'
    Assert-Qualification (-not (Test-Path -LiteralPath $script:registryPath)) 'HKLM:\Software\Paperboat already exists; refusing to overwrite an unmanaged test state.'
    Assert-Qualification (-not (Test-Path -LiteralPath $script:installRoot)) "$($script:installRoot) already exists; refusing to overwrite an unmanaged test state."
    foreach ($definitionName in @('PaperboatHostd.json', 'PaperboatUpdated.json')) {
        $definitionPath = Join-Path $script:stateRoot "services\$definitionName"
        Assert-Qualification (-not (Test-Path -LiteralPath $definitionPath)) "$definitionPath already exists; refusing to overwrite an unmanaged service declaration."
    }
    # The OpenSSH marker cannot distinguish a service that predates this MSI
    # run from one installed by it. Refuse any pre-existing PaperboatSshd so
    # cleanup never mutates an ambiguous owner.
    $paperboatSshd = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object { $_.Name -eq 'PaperboatSshd' })
    Assert-Qualification ($paperboatSshd.Count -eq 0) 'PaperboatSshd already exists; refusing to run MSI qualification against an ambiguous service owner.'
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
    Assert-Qualification ($registry.Channel -eq 'stable') 'Installed channel is incorrect.'

    foreach ($file in @('pb.exe', 'pb-launcher.exe')) {
        $path = Join-Path $script:binaryRoot $file
        Assert-Qualification (Test-Path -LiteralPath $path -PathType Leaf) "Installed payload is missing $path."
    }
    $immutableReleaseRoot = Join-Path $script:installRoot "releases\versions\$ExpectedVersion"
    $versionsRoot = Join-Path $script:installRoot 'releases\versions'
    Assert-InstalledMachineACL -Path $versionsRoot -Directory $true
    Assert-InstalledMachineACL -Path $immutableReleaseRoot -Directory $true
    foreach ($file in @('paperboat-runtime.exe', 'paperboat-hostd.exe', 'paperboat-updater.exe')) {
        $path = Join-Path $immutableReleaseRoot $file
        Assert-Qualification (Test-Path -LiteralPath $path -PathType Leaf) "Installed immutable payload is missing $path."
        Assert-InstalledMachineACL -Path $path -Directory $false
    }
    foreach ($probe in @(
        @{ File = 'paperboat-runtime.exe'; Arguments = @('auth') },
        @{ File = 'paperboat-hostd.exe'; Arguments = @('--version') },
        @{ File = 'paperboat-updater.exe'; Arguments = @('__runtime-worker') }
    )) {
        $rolePath = Join-Path $immutableReleaseRoot $probe.File
        [string[]] $roleArguments = $probe.Arguments
        $output = @(& $rolePath @roleArguments 2>&1)
        $exitCode = $LASTEXITCODE
        Assert-Qualification ($exitCode -eq 2) "$($probe.File) accepted forbidden command '$($probe.Arguments -join ' ')' or returned exit code $exitCode instead of 2: $($output -join ' ')"
        Assert-Qualification (($output -join ' ') -match 'service artifact cannot run that command') "$($probe.File) did not report the role allowlist rejection: $($output -join ' ')"
    }
    Add-QualificationEvent -Name 'role_artifact_allowlist' -Status 'passed' -Detail "version=$ExpectedVersion; runtime_cli_rejected=true; hostd_cli_rejected=true; updater_worker_rejected=true"
    $cliTarget = Join-Path $script:installRoot 'releases\cli-current\pb.exe'
    Assert-Qualification (Test-Path -LiteralPath $cliTarget -PathType Leaf) "Stable CLI target is missing $cliTarget."
    $launcherOutput = @(& (Join-Path $script:binaryRoot 'pb.exe') --version 2>&1)
    $launcherExitCode = $LASTEXITCODE
    Assert-Qualification ($launcherExitCode -eq 0) "Installed stable launcher failed --version with exit code ${launcherExitCode}: $($launcherOutput -join ' ')."
    $launcherVersion = ($launcherOutput -join ' ').Trim()
    $matchingVersionLines = @($launcherOutput | Where-Object { $_ -match "Version\s+$([regex]::Escape($ExpectedVersion))$" })
    Assert-Qualification ($matchingVersionLines.Count -eq 1) "Installed stable launcher returned version '$launcherVersion', expected Version $ExpectedVersion exactly once."
    $stableLauncherHash = (Get-FileHash -LiteralPath (Join-Path $script:binaryRoot 'pb.exe') -Algorithm SHA256).Hash
    $namedLauncherHash = (Get-FileHash -LiteralPath (Join-Path $script:binaryRoot 'pb-launcher.exe') -Algorithm SHA256).Hash
    Assert-Qualification ($stableLauncherHash -eq $namedLauncherHash) 'bin\pb.exe is not the stable Paperboat launcher.'
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
        Assert-Qualification ($service.PathName -match [regex]::Escape((Join-Path $immutableReleaseRoot $expectedBinary))) "$($service.Name) does not point at its immutable installed binary: $($service.PathName)"
        Assert-Qualification ($service.PathName -match [regex]::Escape($expectedArgument)) "$($service.Name) is missing its fixed runtime argument: $($service.PathName)"
    }
    Assert-PaperboatSshdAbsent -Phase "installed-$ExpectedVersion"
    Add-QualificationEvent -Name 'msi_payload_assertions' -Status 'passed' -Detail "version=$ExpectedVersion; services=PaperboatHostd,PaperboatUpdated; stable_launcher_version=true"
}

function Assert-PaperboatSshdAbsent {
    param([Parameter(Mandatory = $true)][string] $Phase)
    $current = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object { $_.Name -eq 'PaperboatSshd' })
    Assert-Qualification ($current.Count -eq 0) "PaperboatSshd appeared during MSI $Phase without an explicitly owned qualification fixture."
    Add-QualificationEvent -Name 'openssh_isolation' -Status 'passed' -Detail "phase=$Phase; service_absent=true"
}

function New-OwnedPreviewCleanupFixture {
	$logicalName = 'msi-cleanup-fixture'
	$hash = [Security.Cryptography.SHA256]::Create()
	try {
		$nameHash = (($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($logicalName)) | ForEach-Object { $_.ToString('x2') }) -join '')
	}
	finally {
		$hash.Dispose()
	}
	$instance = $nameHash.Substring(0, 16)
	$name = 'PaperboatPreview-' + $instance
	$definitionRoot = Join-Path $script:stateRoot 'services'
	$definitionPath = Join-Path $definitionRoot ($name + '.json')
	$previewStateRoot = $script:stateRoot
	$descriptorRoot = Join-Path $script:stateRoot 'previews\active'
	$descriptorPath = Join-Path $descriptorRoot ($instance + '.json')
	$runtimeCurrent = Join-Path $script:installRoot 'releases\runtime-current\paperboat-runtime.exe'
	$runtimeSource = Join-Path $script:installRoot "releases\versions\$Version\paperboat-runtime.exe"
	$runtimeCurrentRoot = Split-Path -Parent $runtimeCurrent
	New-Item -ItemType Directory -Force -Path $definitionRoot, $descriptorRoot | Out-Null
	New-Item -ItemType Directory -Force -Path $runtimeCurrentRoot | Out-Null
    Copy-Item -LiteralPath $runtimeSource -Destination $runtimeCurrent -Force
    Assert-Qualification (Test-Path -LiteralPath $runtimeCurrent -PathType Leaf) 'Runtime-current cleanup fixture was not created.'
    Set-QualificationRuntimeCurrentACL -Path $runtimeCurrentRoot -Directory $true -QualificationSID $script:qualificationSID
    Set-QualificationRuntimeCurrentACL -Path $runtimeCurrent -Directory $false -QualificationSID $script:qualificationSID
    Assert-QualificationRuntimeCurrentACL -Path $runtimeCurrentRoot -Directory $true -QualificationSID $script:qualificationSID
    Assert-QualificationRuntimeCurrentACL -Path $runtimeCurrent -Directory $false -QualificationSID $script:qualificationSID
	$script:runtimeCurrentFixtureCreated = $true
	$arguments = @(
		'__runtime-preview',
		'--state-root', $previewStateRoot,
		'--name', $logicalName,
		'--descriptor', $descriptorPath,
		'--service-definition', $definitionPath,
		'--port', '38123',
		'--indefinite'
	)
    $definition = [ordered]@{
        schema = 'paperboat.windows-service/v1'
        name = $name
        display_name = $name
        description = 'Paperboat MSI cleanup qualification fixture'
        executable = $runtimeCurrent
        arguments = $arguments
        environment = @{ PAPERBOAT_RUNTIME_SERVICE_SCOPE = 'system' }
        account = 'SYSTEM'
	}
	$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
	[IO.File]::WriteAllText($definitionPath, ($definition | ConvertTo-Json -Depth 10), $utf8NoBom)
	$descriptor = [ordered]@{
		schema = 'paperboat.preview-runtime/v1'
		name = $logicalName
		bind_address = '127.0.0.1'
		port = 38123
		service_generation = [uint64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
		indefinite = $true
		service_definition = $definitionPath
	}
	[IO.File]::WriteAllText($descriptorPath, ($descriptor | ConvertTo-Json -Depth 10), $utf8NoBom)
	$commandLine = (Quote-WindowsArgument $definition.executable) + ' ' + (($arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    New-Service `
        -Name $name `
        -BinaryPathName $commandLine `
        -DisplayName 'Paperboat cleanup fixture' `
        -Description 'Paperboat MSI cleanup qualification fixture' `
        -StartupType Manual `
        -ErrorAction Stop | Out-Null
	$script:dynamicPreviewServiceName = $name
	$script:dynamicPreviewDescriptorPath = $descriptorPath
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction Stop
    Assert-Qualification ($null -ne $service) "Owned preview cleanup fixture $name was not registered with SCM."
	Add-QualificationEvent -Name 'dynamic_preview_cleanup_fixture' -Status 'passed' -Detail "logical_name=$logicalName; service=$name; state=stopped; definition=$definitionPath; descriptor=$descriptorPath; executable=$runtimeCurrent; runtime_file=$($script:runtimeCurrentFixtureCreated); runtime_acl=protected; policy=indefinite"
}

function Assert-OwnedPreviewCleanupFixturePresent {
    if ([string]::IsNullOrWhiteSpace($script:dynamicPreviewServiceName)) {
        throw 'qualification_assertion_failed: dynamic preview cleanup fixture was not created.'
    }
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($script:dynamicPreviewServiceName)'" -ErrorAction Stop
    Assert-Qualification ($null -ne $service) "Owned preview service $($script:dynamicPreviewServiceName) disappeared during upgrade."
	Assert-Qualification (Test-Path -LiteralPath (Join-Path $script:stateRoot "services\$($script:dynamicPreviewServiceName).json") -PathType Leaf) 'Owned preview declaration disappeared during upgrade.'
	Assert-Qualification (Test-Path -LiteralPath $script:dynamicPreviewDescriptorPath -PathType Leaf) 'Owned preview descriptor disappeared during upgrade.'
    Assert-Qualification $script:runtimeCurrentFixtureCreated 'Runtime-current cleanup fixture was not recorded as created.'
    $runtimeCurrent = Join-Path $script:installRoot 'releases\runtime-current\paperboat-runtime.exe'
    $runtimeCurrentRoot = Split-Path -Parent $runtimeCurrent
    Assert-Qualification (Test-Path -LiteralPath $runtimeCurrent -PathType Leaf) 'Runtime-current cleanup fixture disappeared during upgrade.'
    Assert-QualificationRuntimeCurrentACL -Path $runtimeCurrentRoot -Directory $true -QualificationSID $script:qualificationSID
    Assert-QualificationRuntimeCurrentACL -Path $runtimeCurrent -Directory $false -QualificationSID $script:qualificationSID
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
	if (-not [string]::IsNullOrWhiteSpace($script:dynamicPreviewDescriptorPath)) {
		Assert-Qualification (-not (Test-Path -LiteralPath $script:dynamicPreviewDescriptorPath)) 'The owned preview descriptor remains after uninstall.'
	}
    Assert-Qualification (-not (Test-Path -LiteralPath $script:installRoot)) "Install root remains after uninstall: $($script:installRoot)"
    if (Test-Path -LiteralPath $script:registryPath) {
        $registry = Get-ItemProperty -LiteralPath $script:registryPath -ErrorAction Stop
        Assert-Qualification ($null -eq $registry.ReleaseVersion) 'Paperboat ReleaseVersion remains after uninstall.'
    }
    if (Test-Path -LiteralPath $script:stateRoot) {
        $productFiles = @(Get-ChildItem -LiteralPath $script:stateRoot -Recurse -File -ErrorAction Stop | Where-Object {
            $_.Name -in @('provisioning-hook.json', 'paperboat-runtime.exe', 'paperboat-hostd.exe', 'paperboat-updater.exe')
        })
        Assert-Qualification ($productFiles.Count -eq 0) 'Product binaries or provisioning metadata remain in ProgramData after uninstall.'
    }
    Assert-PaperboatSshdAbsent -Phase 'uninstall'
    Assert-Qualification (@(Get-InstalledPaperboatProducts).Count -eq 0) 'An ARP Paperboat product entry remains after uninstall.'
    $machinePathEntries = @(Get-MachinePathEntries)
    $expectedPathEntry = ConvertTo-NormalizedMachinePathEntry $script:binaryRoot
    $paperboatPathEntryCount = @($machinePathEntries | Where-Object { $_ -ieq $expectedPathEntry }).Count
    Assert-Qualification ($paperboatPathEntryCount -eq 0) "Paperboat bin remains in the machine PATH after uninstall; found $paperboatPathEntryCount normalized entries for $expectedPathEntry."
    Add-QualificationEvent -Name 'msi_uninstall_assertions' -Status 'passed' -Detail 'fixed services, dynamic preview services, PATH ownership, PaperboatSshd preflight absence, binaries, product registry, ARP entry, and provisioning metadata were verified.'
}

function Assert-PreMsiRuntimeCurrentFixtureIntegrity {
    Assert-QualificationRegularFile -Path $script:preMsiRuntimeCurrentPath
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $script:preMsiRuntimeCurrentPath).Hash.ToUpperInvariant()
    Assert-Qualification ($actualHash -eq $script:preMsiRuntimeCurrentHash) "Pre-MSI runtime-current fixture hash differs from its trusted source: expected=$($script:preMsiRuntimeCurrentHash) actual=$actualHash"
    foreach ($directory in @($script:installRoot, $script:preMsiRuntimeCurrentReleasesRoot, $script:preMsiRuntimeCurrentRoot)) {
        Assert-Qualification (Test-Path -LiteralPath $directory -PathType Container) "Pre-MSI runtime-current ancestor is missing: $directory"
        $item = Get-Item -Force -LiteralPath $directory
        Assert-Qualification ((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Pre-MSI runtime-current ancestor is a reparse point: $directory"
        Assert-QualificationRuntimeCurrentACL -Path $directory -Directory $true -QualificationSID $script:qualificationSID
    }
    Assert-QualificationRuntimeCurrentACL -Path $script:preMsiRuntimeCurrentPath -Directory $false -QualificationSID $script:qualificationSID
}

function Stage-PreMsiRuntimeCurrentFixture {
    $runtimeCurrent = Join-Path $script:installRoot 'releases\runtime-current\paperboat-runtime.exe'
    $runtimeCurrentRoot = Split-Path -Parent $runtimeCurrent
    $releasesRoot = Split-Path -Parent $runtimeCurrentRoot
    Assert-Qualification (-not (Test-Path -LiteralPath $script:installRoot)) "Cannot stage pre-MSI runtime-current fixture because install root already exists: $($script:installRoot)"
    Assert-QualificationRegularFile -Path $resolvedFixturePath
    $outputRootWithSeparator = $resolvedOutputDirectory.TrimEnd('\') + '\'
    Assert-Qualification ($resolvedFixturePath.StartsWith($outputRootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) "Runtime-current fixture must be the hash-bound native artifact under the qualification output root: $resolvedFixturePath"
    Assert-Qualification (-not [String]::Equals($resolvedFixturePath, $runtimeCurrent, [StringComparison]::OrdinalIgnoreCase)) 'Runtime-current fixture source must not be the destination path.'
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedFixturePath).Hash.ToUpperInvariant()

    $script:preMsiRuntimeCurrentPath = $runtimeCurrent
    $script:preMsiRuntimeCurrentRoot = $runtimeCurrentRoot
    $script:preMsiRuntimeCurrentReleasesRoot = $releasesRoot
    $script:preMsiRuntimeCurrentHash = $sourceHash
    # Mark ownership before creating anything so the caller's finally block
    # also cleans up a partially staged fixture, without ever recursing.
    $script:preMsiRuntimeCurrentFixtureCreated = $true
    New-Item -ItemType Directory -Force -Path $runtimeCurrentRoot | Out-Null
    Copy-Item -LiteralPath $resolvedFixturePath -Destination $runtimeCurrent -Force
    Assert-QualificationRegularFile -Path $runtimeCurrent
    $destinationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $runtimeCurrent).Hash.ToUpperInvariant()
    Assert-Qualification ($destinationHash -eq $sourceHash) "Runtime-current fixture hash differs from its trusted source: source=$sourceHash destination=$destinationHash"
    Set-QualificationRuntimeCurrentACL -Path $script:installRoot -Directory $true -QualificationSID $script:qualificationSID
    Set-QualificationRuntimeCurrentACL -Path $releasesRoot -Directory $true -QualificationSID $script:qualificationSID
    Set-QualificationRuntimeCurrentACL -Path $runtimeCurrentRoot -Directory $true -QualificationSID $script:qualificationSID
    Set-QualificationRuntimeCurrentACL -Path $runtimeCurrent -Directory $false -QualificationSID $script:qualificationSID
    Assert-PreMsiRuntimeCurrentFixtureIntegrity
    $script:preMsiRuntimeCurrentStaged = $true
    Add-QualificationEvent -Name 'native_runtime_current_fixture' -Status 'passed' -Detail "path=$runtimeCurrent; source=$resolvedFixturePath; sha256=$sourceHash; owner=SYSTEM; acl=protected"
}

function Remove-PreMsiRuntimeCurrentFixture {
    if (-not $script:preMsiRuntimeCurrentFixtureCreated) {
        return
    }
    $runtimeCurrent = $script:preMsiRuntimeCurrentPath
    $runtimeCurrentRoot = $script:preMsiRuntimeCurrentRoot
    $releasesRoot = $script:preMsiRuntimeCurrentReleasesRoot
    Assert-Qualification (@(Get-PaperboatPreviewServices).Count -eq 0) 'Cannot remove the pre-MSI runtime-current fixture while a PaperboatPreview-* service remains.'
    if (Test-Path -LiteralPath $runtimeCurrent) {
        Assert-PreMsiRuntimeCurrentFixtureIntegrity
        Remove-Item -LiteralPath $runtimeCurrent -Force
        Assert-Qualification (-not (Test-Path -LiteralPath $runtimeCurrent)) "Pre-MSI runtime-current fixture remains after exact-file cleanup: $runtimeCurrent"
    }
    elseif ($script:preMsiRuntimeCurrentStaged) {
        throw "qualification_assertion_failed: staged pre-MSI runtime-current fixture disappeared before cleanup: $runtimeCurrent"
    }
    foreach ($directory in @($runtimeCurrentRoot, $releasesRoot, $script:installRoot)) {
        if (-not (Test-Path -LiteralPath $directory)) {
            continue
        }
        $item = Get-Item -Force -LiteralPath $directory
        Assert-Qualification ($item.PSIsContainer) "Pre-MSI runtime-current cleanup target is not a directory: $directory"
        Assert-Qualification ((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Pre-MSI runtime-current cleanup target is a reparse point: $directory"
        $children = @(Get-ChildItem -Force -LiteralPath $directory -ErrorAction Stop)
        Assert-Qualification ($children.Count -eq 0) "Pre-MSI runtime-current cleanup found unexpected contents under $directory"
        Remove-Item -LiteralPath $directory -Force
        Assert-Qualification (-not (Test-Path -LiteralPath $directory)) "Pre-MSI runtime-current cleanup target remains: $directory"
    }
    Assert-Qualification (-not (Test-Path -LiteralPath $script:installRoot)) "Install root remains after pre-MSI runtime-current cleanup: $($script:installRoot)"
    $script:preMsiRuntimeCurrentFixtureCreated = $false
    $script:preMsiRuntimeCurrentStaged = $false
    Add-QualificationEvent -Name 'native_runtime_current_fixture_cleanup' -Status 'passed' -Detail "path=$runtimeCurrent; exact_file=true; empty_directories=true; install_root_absent=true"
}

function Invoke-NativeGoTests {
    param(
        [Parameter(Mandatory = $true)][string] $RunPattern,
        [Parameter(Mandatory = $true)][string] $Description,
        [Parameter(Mandatory = $true)][string] $Timeout
    )
    if ($NativeTestExecutable -ne '') {
        $resolvedNativeTestExecutable = [IO.Path]::GetFullPath($NativeTestExecutable)
        Assert-Qualification (Test-Path -LiteralPath $resolvedNativeTestExecutable -PathType Leaf) "Native Windows qualification test executable is missing: $resolvedNativeTestExecutable"
        $nativeTestArguments = @('-test.v', '-test.run', $RunPattern, '-test.count', '1', '-test.timeout', $Timeout)
        & $resolvedNativeTestExecutable @nativeTestArguments
    }
    else {
        & go test -count=1 -tags paperboat_native_e2e -v -run $RunPattern ./packaging/windows/e2e
    }
    Assert-Qualification ($LASTEXITCODE -eq 0) "Native Windows qualification Go tests failed for $Description with exit code $LASTEXITCODE."
}

function Invoke-GoQualification {
    $repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
    $previousFixture = $env:PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE
    $env:PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE = $resolvedFixturePath
    try {
        Push-Location $repositoryRoot
        try {
            $preMsiRunPattern = '^(TestNativeSCMHostdAndUpdaterLifecycle|TestNativeConPTYPowerShell51|TestNativeConPTYPowerShell7|TestNativeConPTYCmd|TestNativeLongPathFilesystemLifecycle)$'
            Add-QualificationEvent -Name 'native_go_e2e' -Status 'started' -Detail 'pre-MSI SCM hostd/updater, ConPTY, and long-path tests; durable preview is isolated on RuntimeCurrent'
            Invoke-NativeGoTests -RunPattern $preMsiRunPattern -Description 'pre-MSI native tests' -Timeout '5m'
            Add-QualificationEvent -Name 'native_go_e2e' -Status 'passed' -Detail 'pre-MSI SCM hostd/updater, ConPTY, and long-path tests'

            try {
                Stage-PreMsiRuntimeCurrentFixture
                Assert-PreMsiRuntimeCurrentFixtureIntegrity
                Add-QualificationEvent -Name 'native_go_preview_e2e' -Status 'started' -Detail 'durable preview service against hash-bound RuntimeCurrent fixture'
                Invoke-NativeGoTests -RunPattern '^TestNativeDurablePreviewServiceLifecycle$' -Description 'durable preview RuntimeCurrent test' -Timeout '5m'
                Add-QualificationEvent -Name 'native_go_preview_e2e' -Status 'passed' -Detail 'durable preview service against hash-bound RuntimeCurrent fixture'
            }
            finally {
                Remove-PreMsiRuntimeCurrentFixture
            }

            Add-QualificationEvent -Name 'native_msi_cleanup' -Status 'started' -Detail 'runtime-current PaperboatPreview ownership and bounded slot cleanup'
			$cleanupArguments = @('-test.v', '-test.run', '^TestNativeMSIPreview', '-test.count', '1', '-test.timeout', '2m')
			& $resolvedMsiCleanupTestExecutable @cleanupArguments
			Assert-Qualification ($LASTEXITCODE -eq 0) "Native Windows MSI cleanup qualification failed with exit code $LASTEXITCODE."
			Add-QualificationEvent -Name 'native_msi_cleanup' -Status 'passed' -Detail 'runtime-current service/declaration removal and ownership-conflict preservation cases passed'
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE = $previousFixture
    }
}

function Invoke-OwnerQualificationTest {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][Security.SecureString] $CredentialSecret,
        [Parameter(Mandatory = $true)][string] $OwnerAccount,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [Parameter(Mandatory = $true)][string] $StandardOutputPath,
        [Parameter(Mandatory = $true)][string] $StandardErrorPath
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $resolvedS4UTestExecutable
    $start.WorkingDirectory = $WorkingDirectory
    $start.Arguments = $Arguments -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['PAPERBOAT_WINDOWS_E2E_S4U_OWNER_ACCOUNT'] = $OwnerAccount
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $credentialPointer = [IntPtr]::Zero
    $credentialBytes = $null
    $started = $false
    try {
        Assert-Qualification ($process.Start()) 'Could not start the owner-impersonation qualification process.'
        $started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $credentialPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredentialSecret)
        $credentialByteLength = [Runtime.InteropServices.Marshal]::ReadInt32($credentialPointer, -4)
        Assert-Qualification ($credentialByteLength -gt 0 -and $credentialByteLength -le 512 -and $credentialByteLength % 2 -eq 0) 'Generated qualification credential has an invalid encoded length.'
        $credentialBytes = [byte[]]::new($credentialByteLength)
        [Runtime.InteropServices.Marshal]::Copy($credentialPointer, $credentialBytes, 0, $credentialByteLength)
        $process.StandardInput.BaseStream.Write($credentialBytes, 0, $credentialBytes.Length)
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.Close()
        [Array]::Clear($credentialBytes, 0, $credentialBytes.Length)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credentialPointer)
        $credentialPointer = [IntPtr]::Zero
        Assert-Qualification ($process.WaitForExit(90000)) 'Owner-impersonation qualification process exceeded its 90 second deadline.'
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [IO.File]::WriteAllText($StandardOutputPath, $stdout)
        [IO.File]::WriteAllText($StandardErrorPath, $stderr)
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = @($stdout, $stderr) -join "`n" }
    }
    finally {
        if ($null -ne $credentialBytes) {
            [Array]::Clear($credentialBytes, 0, $credentialBytes.Length)
        }
        if ($credentialPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credentialPointer)
        }
        if ($started -and -not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit()
        }
        $process.Dispose()
    }
}

function Invoke-S4UDPAPIQualification {
    $previousFixture = $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE
    $previousFixtureSHA256 = $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE_SHA256
    $previousOwnerSID = $env:PAPERBOAT_WINDOWS_E2E_S4U_OWNER_SID
    $previousReportPath = $env:PAPERBOAT_WINDOWS_E2E_S4U_REPORT_PATH
    $previousServiceName = $env:PAPERBOAT_WINDOWS_E2E_S4U_SERVICE_NAME
    $ownerName = 'pbq' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $credentialSecret = $null
    $randomBytes = $null
    $owner = $null
    $ownerSID = ''
    $serviceName = 'PaperboatS4UDPAPI-' + [Guid]::NewGuid().ToString('N').Substring(0, 16)
    $programDataRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
    $qualificationParent = Join-Path $programDataRoot 'PaperboatQualification'
    $qualificationRoot = Join-Path $qualificationParent $ownerName
    $workRoot = Join-Path $qualificationRoot 'work'
    $trustedRoot = Join-Path $qualificationRoot 'trusted'
    $qualificationFixture = Join-Path $trustedRoot 's4u-fixture.exe'
    $reportPath = Join-Path $workRoot 's4u-dpapi-report.json'
    $prepareStdout = Join-Path $workRoot 'owner-prepare.stdout.log'
    $prepareStderr = Join-Path $workRoot 'owner-prepare.stderr.log'
    $mutationStdout = Join-Path $workRoot 'owner-mutation.stdout.log'
    $mutationStderr = Join-Path $workRoot 'owner-mutation.stderr.log'
    $bodyFailure = $null
    $cleanupFailures = @()
    try {
        Assert-QualificationAncestorTrusted $programDataRoot
        if (Test-Path -LiteralPath $qualificationParent) {
            Assert-QualificationTrustedRoot $qualificationParent
        }
        else {
            New-QualificationTrustedRootAtomic $qualificationParent
        }
        Assert-QualificationTrustedRoot $qualificationParent
        New-Item -ItemType Directory -Force -Path $qualificationRoot | Out-Null
        Assert-Qualification (((Get-Item -Force -LiteralPath $qualificationRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U qualification transaction root is a reparse point.'
        $credentialSecret = [Security.SecureString]::new()
        foreach ($requiredCharacter in @('a', 'A', '1', '!')) {
            $credentialSecret.AppendChar($requiredCharacter)
        }
        $randomBytes = [byte[]]::new(28)
        $randomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $randomGenerator.GetBytes($randomBytes)
        }
        finally {
            $randomGenerator.Dispose()
        }
        $credentialAlphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*'
        foreach ($randomByte in $randomBytes) {
            $credentialSecret.AppendChar($credentialAlphabet[$randomByte % $credentialAlphabet.Length])
        }
        [Array]::Clear($randomBytes, 0, $randomBytes.Length)
        $credentialSecret.MakeReadOnly()
        $owner = New-LocalUser -Name $ownerName -Password $credentialSecret -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop
        $ownerSID = $owner.SID.Value
        Assert-Qualification (-not [string]::IsNullOrWhiteSpace($ownerSID)) 'Temporary S4U qualification owner has no SID.'
        Test-QualificationTrustValidation -UntrustedSID $ownerSID
        & icacls.exe $qualificationRoot /inheritance:r /grant:r "*${ownerSID}:(OI)(CI)RX" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not protect the S4U qualification root directory.'
        & icacls.exe $qualificationRoot /setowner '*S-1-5-32-544' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not set the trusted owner on the S4U qualification root directory.'
        Assert-QualificationTransactionDirectory -Path $qualificationRoot -OwnerSID $ownerSID -OwnerWritable $false
        New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
        Assert-Qualification (((Get-Item -Force -LiteralPath $workRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Owner-writable S4U work directory is a reparse point.'
        & icacls.exe $workRoot /inheritance:r /grant:r "*${ownerSID}:(OI)(CI)M" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not protect the owner-writable S4U work directory.'
        & icacls.exe $workRoot /setowner '*S-1-5-32-544' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not set the trusted owner on the owner-writable S4U work directory.'
        Assert-QualificationTransactionDirectory -Path $workRoot -OwnerSID $ownerSID -OwnerWritable $true
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U test executable source is a reparse point.'
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UFixturePath).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U fixture source is a reparse point.'
        $sourcePreparationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant()
        $sourceFixtureHashBeforePreparation = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UFixturePath).Hash.ToLowerInvariant()
        $env:PAPERBOAT_WINDOWS_E2E_S4U_OWNER_SID = $ownerSID
        $env:PAPERBOAT_WINDOWS_E2E_S4U_REPORT_PATH = $reportPath
        $env:PAPERBOAT_WINDOWS_E2E_S4U_SERVICE_NAME = $serviceName
        $prepareArguments = @('-test.v', '-test.run', '^TestNativePrepareS4UDPAPIQualification$', '-test.count', '1', '-test.timeout', '1m')
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point before owner-context preparation.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed immediately before owner-context preparation.'
        $prepare = Invoke-OwnerQualificationTest -Arguments $prepareArguments -CredentialSecret $credentialSecret -OwnerAccount "$env:COMPUTERNAME\$ownerName" -WorkingDirectory $workRoot -StandardOutputPath $prepareStdout -StandardErrorPath $prepareStderr
        Assert-Qualification (Test-Path -LiteralPath $prepareStdout -PathType Leaf) 'Owner preparation stdout redirect was not created in the qualification directory.'
        Assert-Qualification (Test-Path -LiteralPath $prepareStderr -PathType Leaf) 'Owner preparation stderr redirect was not created in the qualification directory.'
        if ($prepare.ExitCode -ne 0) {
            throw "Owner-context Credential Manager migration preparation failed with exit code $($prepare.ExitCode): $($prepare.Output)"
        }

        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point during owner-context preparation.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed during owner-context preparation.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UFixturePath).Hash.ToLowerInvariant() -eq $sourceFixtureHashBeforePreparation) 'S4U fixture source changed during owner-context preparation.'
        Assert-QualificationAncestorTrusted $programDataRoot
        Assert-QualificationAncestorTrusted $qualificationParent
        Assert-QualificationTransactionDirectory -Path $qualificationRoot -OwnerSID $ownerSID -OwnerWritable $false
        Assert-QualificationTransactionDirectory -Path $workRoot -OwnerSID $ownerSID -OwnerWritable $true
        New-Item -ItemType Directory -Force -Path $trustedRoot | Out-Null
        & icacls.exe $trustedRoot /inheritance:r /grant:r "*${ownerSID}:(OI)(CI)RX" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not protect the trusted S4U fixture directory.'
        & icacls.exe $trustedRoot /setowner '*S-1-5-32-544' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not set the trusted owner on the trusted S4U fixture directory.'
        Assert-QualificationTransactionDirectory -Path $trustedRoot -OwnerSID $ownerSID -OwnerWritable $false
        Assert-Qualification (((Get-Item -Force -LiteralPath $trustedRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Trusted S4U fixture directory is a reparse point.'
        Copy-Item -LiteralPath $resolvedS4UFixturePath -Destination $qualificationFixture -Force
        Assert-Qualification (Test-Path -LiteralPath $qualificationFixture -PathType Leaf) 'S4U fixture executable was not isolated in the trusted directory.'
        Assert-Qualification (((Get-Item -Force -LiteralPath $qualificationFixture).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U fixture executable is a reparse point.'
        & icacls.exe $qualificationFixture /inheritance:r /grant:r "*${ownerSID}:RX" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not protect the trusted S4U fixture executable.'
        & icacls.exe $qualificationFixture /setowner '*S-1-5-32-544' | Out-Null
        Assert-Qualification ($LASTEXITCODE -eq 0) 'Could not set the trusted owner on the S4U fixture executable.'
        $trustedFixtureHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $qualificationFixture).Hash.ToLowerInvariant()
        Assert-Qualification ($trustedFixtureHash -eq $sourceFixtureHashBeforePreparation) 'Trusted S4U fixture differs from its source.'
        $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE = $qualificationFixture
        $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE_SHA256 = $trustedFixtureHash

        $mutationArguments = @('-test.v', '-test.run', '^TestNativeOwnerCannotMutateS4UFixture$', '-test.count', '1', '-test.timeout', '1m')
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point before owner immutability probe.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed immediately before owner immutability probe.'
        $mutation = Invoke-OwnerQualificationTest -Arguments $mutationArguments -CredentialSecret $credentialSecret -OwnerAccount "$env:COMPUTERNAME\$ownerName" -WorkingDirectory $workRoot -StandardOutputPath $mutationStdout -StandardErrorPath $mutationStderr
        Assert-Qualification (Test-Path -LiteralPath $mutationStdout -PathType Leaf) 'Owner mutation-probe stdout redirect was not created in the work directory.'
        Assert-Qualification (Test-Path -LiteralPath $mutationStderr -PathType Leaf) 'Owner mutation-probe stderr redirect was not created in the work directory.'
        if ($mutation.ExitCode -ne 0) {
            throw "Owner fixture immutability probe failed with exit code $($mutation.ExitCode): $($mutation.Output)"
        }
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point during owner immutability probe.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed during owner immutability probe.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $qualificationFixture).Hash.ToLowerInvariant() -eq $trustedFixtureHash) 'Trusted S4U fixture changed during owner immutability probe.'

        Add-QualificationEvent -Name 'native_s4u_dpapi' -Status 'started' -Detail "owner_sid=$ownerSID; architecture=$Architecture; owner_migration_prepared=true"
        Assert-QualificationAncestorTrusted $programDataRoot
        Assert-QualificationAncestorTrusted $qualificationParent
        Assert-QualificationTransactionDirectory -Path $qualificationRoot -OwnerSID $ownerSID -OwnerWritable $false
        Assert-QualificationTransactionDirectory -Path $trustedRoot -OwnerSID $ownerSID -OwnerWritable $false
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U test executable became a reparse point immediately before logged-out qualification.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U test executable changed immediately before logged-out qualification.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UFixturePath).Hash.ToLowerInvariant() -eq $trustedFixtureHash) 'S4U fixture source changed immediately before SCM qualification.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $qualificationFixture).Hash.ToLowerInvariant() -eq $trustedFixtureHash) 'Trusted S4U fixture changed immediately before SCM qualification.'
        $arguments = @('-test.v', '-test.run', '^TestNativeLoggedOutS4UDPAPIQualification$', '-test.count', '1', '-test.timeout', '2m')
        & $resolvedS4UTestExecutable @arguments
        Assert-Qualification ($LASTEXITCODE -eq 0) "Native logged-out S4U DPAPI qualification failed with exit code $LASTEXITCODE."
        Add-QualificationEvent -Name 'native_s4u_dpapi' -Status 'passed' -Detail "owner_sid=$ownerSID; architecture=$Architecture; dpapi_readable=true; credential_manager_migration=true"
    }
    catch {
        $invocation = $_.InvocationInfo
        $scriptName = if ([string]::IsNullOrWhiteSpace($invocation.ScriptName)) { '<unknown>' } else { Split-Path -Leaf $invocation.ScriptName }
        $stack = ([string]$_.ScriptStackTrace).Replace("`r", '').Replace("`n", ' > ')
        $bodyFailure = "$($_.Exception.Message) [exception=$($_.Exception.GetType().FullName); error_id=$($_.FullyQualifiedErrorId); command=$($invocation.MyCommand.Name); script=$scriptName; line=$($invocation.ScriptLineNumber); column=$($invocation.OffsetInLine); stack=$stack]"
    }
    finally {
        $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE = $previousFixture
        $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE_SHA256 = $previousFixtureSHA256
        $env:PAPERBOAT_WINDOWS_E2E_S4U_OWNER_SID = $previousOwnerSID
        $env:PAPERBOAT_WINDOWS_E2E_S4U_REPORT_PATH = $previousReportPath
        $env:PAPERBOAT_WINDOWS_E2E_S4U_SERVICE_NAME = $previousServiceName
        try {
            $qualificationService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -ne $qualificationService) {
                if ($qualificationService.Status -ne 'Stopped') {
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                    $qualificationService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                }
                & sc.exe delete $serviceName | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "sc.exe delete returned exit code $LASTEXITCODE"
                }
                for ($attempt = 0; $attempt -lt 20; $attempt++) {
                    if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
                        break
                    }
                    Start-Sleep -Milliseconds 250
                }
                if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
                    throw 'qualification service remains after bounded stop/delete cleanup'
                }
            }
        }
        catch {
            $cleanupFailures += "service $serviceName cleanup: $($_.Exception.Message)"
        }
        if (-not [string]::IsNullOrWhiteSpace($ownerSID)) {
            try {
                $profileDeadline = [DateTime]::UtcNow.AddSeconds(30)
                $lastProfileError = $null
                do {
                    $ownerProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$ownerSID'" -ErrorAction Stop)
                    if ($ownerProfiles.Count -eq 0) {
                        break
                    }
                    foreach ($ownerProfile in $ownerProfiles) {
                        try {
                            Remove-CimInstance -InputObject $ownerProfile -ErrorAction Stop
                            $lastProfileError = $null
                        }
                        catch {
                            $lastProfileError = $_.Exception
                        }
                    }
                    if ([DateTime]::UtcNow -lt $profileDeadline) {
                        Start-Sleep -Milliseconds 500
                    }
                } while ([DateTime]::UtcNow -lt $profileDeadline)
                $remainingProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$ownerSID'" -ErrorAction Stop)
                if ($remainingProfiles.Count -ne 0) {
                    if ($null -ne $lastProfileError) {
                        throw "temporary owner profile remains after bounded cleanup: $($lastProfileError.Message)"
                    }
                    throw 'temporary owner profile remains after bounded cleanup'
                }
            }
            catch {
                $cleanupFailures += "profile $ownerSID cleanup: $($_.Exception.Message)"
            }
        }
        if ($null -ne $owner) {
            try {
                Remove-LocalUser -Name $ownerName -ErrorAction Stop
                if ($null -ne (Get-LocalUser -Name $ownerName -ErrorAction SilentlyContinue)) {
                    throw 'temporary local owner remains after cleanup'
                }
            }
            catch {
                $cleanupFailures += "local user $ownerName cleanup: $($_.Exception.Message)"
            }
        }
        if (Test-Path -LiteralPath $trustedRoot) {
            try {
                Remove-Item -LiteralPath $trustedRoot -Recurse -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $trustedRoot) {
                    throw 'trusted qualification root remains after cleanup'
                }
            }
            catch {
                $cleanupFailures += "trusted root $trustedRoot cleanup: $($_.Exception.Message)"
            }
        }
        if (Test-Path -LiteralPath $workRoot) {
            try {
                Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $workRoot) {
                    throw 'owner work root remains after cleanup'
                }
            }
            catch {
                $cleanupFailures += "work root $workRoot cleanup: $($_.Exception.Message)"
            }
        }
        if (Test-Path -LiteralPath $qualificationRoot) {
            try {
                Remove-Item -LiteralPath $qualificationRoot -Recurse -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $qualificationRoot) {
                    throw 'qualification transaction root remains after cleanup'
                }
            }
            catch {
                $cleanupFailures += "qualification root $qualificationRoot cleanup: $($_.Exception.Message)"
            }
        }
        if ($null -ne $randomBytes) {
            [Array]::Clear($randomBytes, 0, $randomBytes.Length)
        }
        if ($null -ne $credentialSecret) {
            $credentialSecret.Dispose()
        }
    }
    if ($null -ne $bodyFailure -or $cleanupFailures.Count -gt 0) {
        $allFailures = @(@($bodyFailure) + $cleanupFailures | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        throw ($allFailures -join '; ')
    }
}

function Invoke-LegacySecurityMigrationQualification {
    Add-QualificationEvent -Name 'native_legacy_security_migration' -Status 'started' -Detail 'isolated owner-FULL root/config/token ACL fixture'
    $arguments = @('-test.v', '-test.run', '^TestNativeLegacyOwnerFullSecurityMigration$', '-test.count', '1', '-test.timeout', '2m')
    & $resolvedHostinstallTestExecutable @arguments
    Assert-Qualification ($LASTEXITCODE -eq 0) "Native legacy Windows security migration qualification failed with exit code $LASTEXITCODE."
    Add-QualificationEvent -Name 'native_legacy_security_migration' -Status 'passed' -Detail 'owner_full_rejected_before=true; owner_read_only_after=true; config_unchanged=true'
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
        stability = 'stable'
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

$bodyFailure = $null
$cleanupFailure = $null
try {
    Assert-Preflight
    Invoke-S4UDPAPIQualification
    Invoke-LegacySecurityMigrationQualification
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
    $bodyFailure = $_
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
            $cleanupFailure = $_
            Add-QualificationEvent -Name 'failure_cleanup' -Status 'failed' -Detail $_.Exception.Message
        }
    }
    $failureText = ($script:events | Where-Object { $_.status -eq 'failed' } | Select-Object -First 1).detail
    Write-QualificationReport -Failure $failureText
}
if ($null -ne $bodyFailure) {
    throw $bodyFailure
}
if ($null -ne $cleanupFailure) {
    throw $cleanupFailure
}
