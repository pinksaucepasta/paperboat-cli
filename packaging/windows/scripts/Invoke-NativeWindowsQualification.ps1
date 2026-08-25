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

    [Parameter(Mandatory = $true)]
    [string] $NativeTestExecutable,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:events = @()
$script:preflightPassed = $false
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
$script:nativeTestEvidenceSequence = 0
$script:nativeTestSHA256 = $null
$script:nativeTestLength = $null
$script:preexistingPaperboatState = $null
$script:launchedQualificationProcesses = @()
$script:qualificationProcessIdentityFailures = @()
$script:qualificationProcessRegistrationFailures = @()
$script:qualificationProcessContract = 'synchronous_descendants_required'
$script:msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$script:icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
$script:serviceControl = Join-Path $env:SystemRoot 'System32\sc.exe'
$script:msiOperationTimeoutMilliseconds = 5 * 60 * 1000
$script:msiTerminationGraceMilliseconds = 15 * 1000
$script:nativeCommandTimeoutMilliseconds = 30 * 1000
$script:nativeTestTimeoutMilliseconds = 5 * 60 * 1000 + 30 * 1000
$script:streamDrainTimeoutMilliseconds = 15 * 1000
$script:installRoot = Join-Path ${env:ProgramFiles} 'Paperboat'
$script:binaryRoot = Join-Path $script:installRoot 'bin'
$script:stateRoot = Join-Path ${env:ProgramData} 'Paperboat'
$script:registryPath = 'HKLM:\Software\Paperboat'
$script:openSSHRegistryPath = 'HKLM:\Software\Paperboat\OpenSSH'

$resolvedOutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory -ErrorAction Stop
$outputDirectoryItem = Get-Item -Force -LiteralPath $resolvedOutputDirectory -ErrorAction Stop
if (-not $outputDirectoryItem.PSIsContainer -or -not [IO.Directory]::Exists($resolvedOutputDirectory)) {
    throw "qualification_output_directory_invalid: output path is not a real directory: $resolvedOutputDirectory"
}
if (($outputDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "qualification_output_directory_invalid: output path is a reparse point: $resolvedOutputDirectory"
}
$resolvedMsiPath = [IO.Path]::GetFullPath($MsiPath)
$resolvedUpgradeMsiPath = [IO.Path]::GetFullPath($UpgradeMsiPath)
$resolvedFixturePath = [IO.Path]::GetFullPath($ServiceFixturePath)
$resolvedS4UFixturePath = [IO.Path]::GetFullPath($S4UFixturePath)
$resolvedS4UTestExecutable = [IO.Path]::GetFullPath($S4UTestExecutable)
$resolvedHostinstallTestExecutable = [IO.Path]::GetFullPath($HostinstallTestExecutable)
$resolvedMsiCleanupTestExecutable = [IO.Path]::GetFullPath($MsiCleanupTestExecutable)
$resolvedNativeTestExecutable = [IO.Path]::GetFullPath($NativeTestExecutable)
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

function New-NativeTestExecutionEvidence {
    param(
        [Parameter(Mandatory = $true)][string] $ExecutablePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $RunPattern,
        [Parameter(Mandatory = $true)][string] $Description,
        [Parameter(Mandatory = $true)][string] $EvidenceName,
        [Parameter(Mandatory = $true)][int] $ExitCode,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]] $Output
    )
    $runTests = @()
    $passedTests = @()
    $failedTests = @()
    $skippedTests = @()
    foreach ($line in @($Output | ForEach-Object { [string]$_ })) {
        if ($line -match '^\s*=== RUN\s+(.+?)\s*$') {
            $runTests += $Matches[1]
            continue
        }
        if ($line -match '^\s*---\s+(PASS|FAIL|SKIP):\s+(.+?)(?:\s+\([^)]*\))?\s*$') {
            switch ($Matches[1]) {
                'PASS' { $passedTests += $Matches[2] }
                'FAIL' { $failedTests += $Matches[2] }
                'SKIP' { $skippedTests += $Matches[2] }
            }
        }
    }

    $script:nativeTestEvidenceSequence++
    $safeName = [regex]::Replace($EvidenceName, '[^A-Za-z0-9_.-]', '_')
    $sequence = '{0:D3}' -f $script:nativeTestEvidenceSequence
    $evidencePath = Join-Path $resolvedOutputDirectory "native-test-$sequence-$safeName.json"
    $outputPath = Join-Path $resolvedOutputDirectory "native-test-$sequence-$safeName.log"
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($outputPath, ((@($Output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine) + [Environment]::NewLine), $utf8NoBom)
    $evidence = [ordered]@{
        schema = 'paperboat.windows-native-test-execution/v1'
        machine_readable = $true
        description = $Description
        executable = $ExecutablePath
        arguments = @($Arguments)
        run_pattern = $RunPattern
        exit_code = $ExitCode
        tests_run = @($runTests)
        tests_run_count = @($runTests).Count
        tests_passed = @($passedTests)
        tests_passed_count = @($passedTests).Count
        tests_failed = @($failedTests)
        tests_failed_count = @($failedTests).Count
        tests_skipped = @($skippedTests)
        tests_skipped_count = @($skippedTests).Count
        output_log = $outputPath
    }
    [IO.File]::WriteAllText($evidencePath, ($evidence | ConvertTo-Json -Depth 10), $utf8NoBom)
    return [pscustomobject]@{
        EvidencePath = $evidencePath
        OutputPath = $outputPath
        ExitCode = $ExitCode
        TestsRun = @($runTests)
        TestsRunCount = @($runTests).Count
        TestsPassed = @($passedTests)
        TestsPassedCount = @($passedTests).Count
        TestsFailed = @($failedTests)
        TestsFailedCount = @($failedTests).Count
        TestsSkipped = @($skippedTests)
        TestsSkippedCount = @($skippedTests).Count
    }
}

function Assert-NativeTestExecutionEvidence {
    param(
        [Parameter(Mandatory = $true)][psobject] $Evidence,
        [Parameter(Mandatory = $true)][string] $Description
    )
    Assert-Qualification ($Evidence.ExitCode -eq 0) "Native Windows qualification test pattern failed for $Description with exit code $($Evidence.ExitCode). Evidence: $($Evidence.EvidencePath)."
    Assert-Qualification ($Evidence.TestsRunCount -gt 0) "Native Windows qualification matched zero tests for $Description. Pattern execution evidence: $($Evidence.EvidencePath)."
    Assert-Qualification ($Evidence.TestsPassedCount -gt 0) "Native Windows qualification completed no passing tests for $Description. Pattern execution evidence: $($Evidence.EvidencePath)."
    Assert-Qualification ($Evidence.TestsFailedCount -eq 0) "Native Windows qualification reported failed tests for $Description. Pattern execution evidence: $($Evidence.EvidencePath)."
}

function Get-OwnerQualificationStages {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Output)
    $allowedActionStages = @(
        'owner-process-validate', 'thread-token-absent', 'effective-owner',
        'profile-ready', 'local-app-data',
        'working-directory', 'owner-access', 'atomic-file',
        'file-secret-store', 'keyring-write', 'credential-manager-write',
        'credential-manager-migrate', 'identity-create', 'identity-control',
        'identity-open', 'identity-registration-read', 'identity-control-read',
        'security-assertions', 'body-complete'
    )
	$allowedCleanupStages = @(
		'profile-load-cleanup', 'profile-load-cleaned',
		'impersonation-revert', 'impersonation-reverted',
		'impersonation-token-close', 'impersonation-token-closed',
		'profile-unload', 'profile-unloaded',
		'interactive-token-close', 'interactive-token-closed'
	)
	$allowedCleanupFailures = @(
		'profile-load-cleanup', 'profile-unload-blocked',
		'impersonation-revert', 'impersonation-token-close',
		'profile-unload', 'interactive-token-close'
	)
    $actionStage = 'unreported'
	$cleanupStage = 'not-started'
	$cleanupFailure = 'none'
    $boundedTail = if ($Output.Length -gt 8192) { $Output.Substring($Output.Length - 8192) } else { $Output }
    foreach ($line in @($boundedTail -split "`r?`n")) {
        if ($line -match '^paperboat-s4u-action-stage:([a-z0-9-]+)$' -and $allowedActionStages -contains $Matches[1]) {
            $actionStage = $Matches[1]
        }
		if ($line -match '^paperboat-s4u-cleanup-stage:([a-z0-9-]+)$' -and $allowedCleanupStages -contains $Matches[1]) {
			$cleanupStage = $Matches[1]
		}
		if ($cleanupFailure -eq 'none' -and $line -match '^paperboat-s4u-cleanup-failure:([a-z0-9-]+)$' -and $allowedCleanupFailures -contains $Matches[1]) {
			$cleanupFailure = $Matches[1]
		}
    }
    return [pscustomobject]@{ ActionStage = $actionStage; CleanupStage = $cleanupStage; CleanupFailure = $cleanupFailure }
}

function Invoke-NativeTestPattern {
    param(
        [Parameter(Mandatory = $true)][string] $ExecutablePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $RunPattern,
        [Parameter(Mandatory = $true)][string] $Description,
        [Parameter(Mandatory = $true)][string] $EvidenceName
    )
    $output = @()
    $exitCode = -1
    try {
        $nativeResult = Invoke-NativeCommandCapture -ExecutablePath $ExecutablePath -Arguments $Arguments -TimeoutMilliseconds $script:nativeTestTimeoutMilliseconds
        $output = @($nativeResult.Output)
        $exitCode = [int]$nativeResult.ExitCode
    }
    catch {
        $output += [string]$_
    }
    $evidence = New-NativeTestExecutionEvidence -ExecutablePath $ExecutablePath -Arguments $Arguments -RunPattern $RunPattern -Description $Description -EvidenceName $EvidenceName -ExitCode $exitCode -Output $output
    Assert-NativeTestExecutionEvidence -Evidence $evidence -Description $Description
    return $evidence
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
        $evidenceName = if ($Directory) { 'runtime-current-acl-directory' } else { 'runtime-current-acl-file' }
        $null = Invoke-NativeTestPattern -ExecutablePath $resolvedHostinstallTestExecutable -Arguments $arguments -RunPattern '^TestNativeApplyQualificationRuntimeCurrentACL$' -Description 'runtime-current ACL helper' -EvidenceName $evidenceName
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
        $foreignOwnerResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($foreignOwnerPath, '/setowner', "*$UntrustedSID")
        Assert-Qualification ($foreignOwnerResult.ExitCode -eq 0) "Could not create the hostile-owner qualification fixture: $($foreignOwnerResult.Output -join ' ')"
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
        $deleteACEResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($deleteACEPath, '/grant', "*${UntrustedSID}:D")
        Assert-Qualification ($deleteACEResult.ExitCode -eq 0) "Could not create the hostile delete-ACE qualification fixture: $($deleteACEResult.Output -join ' ')"
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

function Stop-QualificationProcess {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process] $Process,
        [Parameter(Mandatory = $true)][bool] $HandlePinned
    )
    # Every caller pins Process.Handle immediately after Start. Never fall back to
    # raw-PID termination: a reused PID could target an unrelated process.
    Assert-Qualification $HandlePinned 'Qualification process termination requires a pinned process handle.'
    try {
        if ($Process.HasExited) {
            return
        }
    }
    catch {
        throw "Could not inspect qualification process before termination: $($_.Exception.Message)"
    }
    $targetProcessId = [uint32]$Process.Id
    try {
        if (-not $Process.HasExited) {
            $Process.Kill()
        }
    }
    catch {
        try {
            if (-not $Process.HasExited) {
                throw "Qualification process could not be terminated: $($_.Exception.Message)"
            }
        }
        catch {
            throw
        }
    }
    try {
        Assert-Qualification ($Process.WaitForExit($script:msiTerminationGraceMilliseconds)) "Qualification process $targetProcessId did not terminate within the bounded deadline."
    }
    catch {
        if (-not $Process.HasExited) {
            throw
        }
    }
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
    $process = $null
    $processRecord = $null
    $started = $false
    $handlePinned = $false
    try {
        try {
            $process = Start-Process -FilePath $script:msiexec -ArgumentList $argumentLine -PassThru -WindowStyle Hidden -ErrorAction Stop
            $started = $true
            $processHandle = $process.Handle
            Assert-Qualification ($processHandle -ne [IntPtr]::Zero) 'msiexec returned an invalid process handle.'
            $handlePinned = $true
            $processRecord = Register-QualificationProcess -Process $process
        }
        catch {
            Add-QualificationEvent -Name "msiexec_$Operation" -Status 'failed' -Detail "start_failed=true; log=$LogPath"
            throw
        }
        if (-not $process.WaitForExit($script:msiOperationTimeoutMilliseconds)) {
            $processId = [uint32]$process.Id
            $terminationFailure = $null
            try {
                Assert-Qualification $handlePinned 'msiexec timeout cleanup has no pinned process handle.'
                if (-not $process.HasExited) {
                    $process.Kill()
                }
            }
            catch {
                $terminationFailure = $_.Exception.Message
            }
            $terminated = $false
            try {
                $terminated = $process.WaitForExit($script:msiTerminationGraceMilliseconds)
            }
            catch {
                if ($null -eq $terminationFailure) {
                    $terminationFailure = $_.Exception.Message
                }
            }
            $detail = "timeout_ms=$($script:msiOperationTimeoutMilliseconds); process_id=$processId; terminated=$terminated; log=$LogPath"
            if (-not [string]::IsNullOrWhiteSpace($terminationFailure)) {
                $detail += '; termination_error=' + $terminationFailure
            }
            Add-QualificationEvent -Name "msiexec_$Operation" -Status 'failed' -Detail $detail
            throw "msiexec $Operation exceeded the bounded timeout. $detail"
        }
        $exitCode = [int]$process.ExitCode
        if ($exitCode -ne 0 -and $exitCode -ne 3010) {
            Add-QualificationEvent -Name "msiexec_$Operation" -Status 'failed' -Detail "exit_code=$exitCode; log=$LogPath"
            throw "msiexec $Operation returned exit code $exitCode. See $LogPath."
        }
        Add-QualificationEvent -Name "msiexec_$Operation" -Status 'passed' -Detail "exit_code=$exitCode; log=$LogPath"
    }
    finally {
        if ($null -ne $process) {
            try {
                if ($started -and (-not $handlePinned -or $null -eq $processRecord)) {
                    $script:qualificationProcessRegistrationFailures += "kind=msiexec; handle_pinned=$handlePinned; record_present=$($null -ne $processRecord)"
                }
                if ($started -and $handlePinned -and $null -eq $processRecord -and -not $process.HasExited) {
                    Stop-QualificationProcess -Process $process -HandlePinned $handlePinned
                }
                if ($null -ne $processRecord) {
                    Complete-QualificationProcess -Record $processRecord -Process $process
                }
            }
            finally {
                $process.Dispose()
            }
        }
    }
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
    $root = Get-Item -Force -LiteralPath $definitionRoot -ErrorAction Stop
    Assert-Qualification ($root.PSIsContainer) "Paperboat service declaration root is not a directory: $definitionRoot"
    Assert-Qualification ((($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Paperboat service declaration root is a reparse point: $definitionRoot"
    $declarations = @(Get-ChildItem -Force -LiteralPath $definitionRoot -Filter 'PaperboatPreview-*.json' -ErrorAction Stop)
    foreach ($declaration in $declarations) {
        Assert-Qualification (-not $declaration.PSIsContainer) "Paperboat preview declaration is a directory: $($declaration.FullName)"
        Assert-Qualification ((($declaration.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Paperboat preview declaration is a reparse point: $($declaration.FullName)"
    }
    return $declarations
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

function Get-QualificationProcessCreationKey {
    param([Parameter(Mandatory = $true)][DateTime] $Timestamp)
    $utcTicks = $Timestamp.ToUniversalTime().Ticks
    return [int64]($utcTicks - ($utcTicks % 10))
}

function Register-QualificationProcess {
    param([Parameter(Mandatory = $true)][Diagnostics.Process] $Process)
    $imagePath = [IO.Path]::GetFullPath([string]$Process.StartInfo.FileName)
    $record = [pscustomobject]@{
        ProcessId = [uint32]$Process.Id
        StartUtc = $Process.StartTime.ToUniversalTime()
        StartCreationKey = Get-QualificationProcessCreationKey $Process.StartTime
        ImagePath = $imagePath
        EndUtc = $null
        EndCreationKey = $null
    }
    $script:launchedQualificationProcesses += $record
    return $record
}

function Complete-QualificationProcess {
    param(
        [Parameter(Mandatory = $true)][psobject] $Record,
        [Parameter(Mandatory = $true)][Diagnostics.Process] $Process
    )
    if ($Process.HasExited) {
        $Record.EndUtc = $Process.ExitTime.ToUniversalTime()
        $Record.EndCreationKey = Get-QualificationProcessCreationKey $Process.ExitTime
    }
}

function Test-QualificationPathWithinRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Root
    )
    try {
        $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    }
    catch {
        return $false
    }
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-QualificationOwnedProcesses {
    $qualificationRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'PaperboatQualification'
    $ownedRoots = @($script:installRoot, $qualificationRoot, $resolvedOutputDirectory)
    $ownedExecutables = @(
        $resolvedFixturePath,
        $resolvedS4UFixturePath,
        $resolvedS4UTestExecutable,
        $resolvedHostinstallTestExecutable,
        $resolvedMsiCleanupTestExecutable,
        $resolvedNativeTestExecutable
    )
    $allProcesses = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $ownedProcesses = [Collections.ArrayList]::new()
    $ownedKeys = @{}
    $script:qualificationProcessIdentityFailures = @()
    foreach ($candidate in $allProcesses) {
        if ([uint32]$candidate.ProcessId -eq [uint32]$PID) {
            continue
        }
        $executablePath = [string]$candidate.ExecutablePath
        $owned = $false
        if (-not [string]::IsNullOrWhiteSpace($executablePath)) {
            foreach ($root in $ownedRoots) {
                if (Test-QualificationPathWithinRoot -Path $executablePath -Root $root) {
                    $owned = $true
                    break
                }
            }
            if (-not $owned) {
                foreach ($ownedExecutable in $ownedExecutables) {
                    if ($executablePath.Equals($ownedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
                        $owned = $true
                        break
                    }
                }
            }
        }
        if ($owned) {
            $creationUtc = ([DateTime]$candidate.CreationDate).ToUniversalTime()
            $creationKey = Get-QualificationProcessCreationKey $creationUtc
            $key = "$([uint32]$candidate.ProcessId):$creationKey"
            if (-not $ownedKeys.ContainsKey($key)) {
                $ownedKeys[$key] = $true
                $null = $ownedProcesses.Add($candidate)
            }
        }
    }

    foreach ($record in $script:launchedQualificationProcesses) {
        $recordStartUtc = [DateTime]$record.StartUtc
        $recordStartKey = [int64]$record.StartCreationKey
        $liveLaunches = @($allProcesses | Where-Object {
            if ([uint32]$_.ProcessId -ne [uint32]$record.ProcessId) {
                return $false
            }
            $creationUtc = ([DateTime]$_.CreationDate).ToUniversalTime()
            $creationKey = Get-QualificationProcessCreationKey $creationUtc
            $imagePath = [string]$_.ExecutablePath
            return $creationKey -eq $recordStartKey -and
                -not [string]::IsNullOrWhiteSpace($imagePath) -and
                ([IO.Path]::GetFullPath($imagePath)).Equals([string]$record.ImagePath, [StringComparison]::OrdinalIgnoreCase)
        })
        Assert-Qualification ($liveLaunches.Count -le 1) "Launch identity is ambiguous for PID $($record.ProcessId)."
        if ($null -eq $record.EndUtc) {
            if ($liveLaunches.Count -ne 1) {
                $script:qualificationProcessIdentityFailures += "pid=$($record.ProcessId),start=$($recordStartUtc.ToString('o')),image=$($record.ImagePath),state=nonterminal_identity_missing"
                continue
            }
            $liveLaunch = $liveLaunches[0]
            $liveCreationUtc = ([DateTime]$liveLaunch.CreationDate).ToUniversalTime()
            $liveCreationKey = Get-QualificationProcessCreationKey $liveCreationUtc
            $liveKey = "$([uint32]$liveLaunch.ProcessId):$liveCreationKey"
            if (-not $ownedKeys.ContainsKey($liveKey)) {
                $ownedKeys[$liveKey] = $true
                $null = $ownedProcesses.Add($liveLaunch)
            }
        }
        elseif ($liveLaunches.Count -gt 0) {
            $script:qualificationProcessIdentityFailures += "pid=$($record.ProcessId),start=$($recordStartUtc.ToString('o')),image=$($record.ImagePath),state=terminal_identity_still_live"
        }
        $recordEndKey = if ($null -ne $record.EndCreationKey) { [int64]$record.EndCreationKey } else { Get-QualificationProcessCreationKey ([DateTime]::UtcNow) }
        foreach ($candidate in $allProcesses) {
            if ([uint32]$candidate.ProcessId -eq [uint32]$PID -or [uint32]$candidate.ParentProcessId -ne [uint32]$record.ProcessId) {
                continue
            }
            $creationUtc = ([DateTime]$candidate.CreationDate).ToUniversalTime()
            $creationKey = Get-QualificationProcessCreationKey $creationUtc
            if ($creationKey -lt $recordStartKey -or $creationKey -gt $recordEndKey) {
                continue
            }
            $key = "$([uint32]$candidate.ProcessId):$creationKey"
            if (-not $ownedKeys.ContainsKey($key)) {
                $ownedKeys[$key] = $true
                $null = $ownedProcesses.Add($candidate)
            }
        }
    }
    return @($ownedProcesses)
}

function Assert-NoQualificationProcessResidue {
    param([Parameter(Mandatory = $true)][string] $Phase)
    $processes = @(Get-QualificationOwnedProcesses)
    $detail = @($processes | ForEach-Object {
        "pid=$($_.ProcessId),name=$($_.Name),path=$([string]$_.ExecutablePath)"
    }) -join '; '
    Assert-Qualification ($script:qualificationProcessRegistrationFailures.Count -eq 0) "Qualification launches were not safely registered during $Phase`: $($script:qualificationProcessRegistrationFailures -join '; ')"
    Assert-Qualification ($script:qualificationProcessIdentityFailures.Count -eq 0) "Qualification process identities could not be resolved during $Phase`: $($script:qualificationProcessIdentityFailures -join '; ')"
    Assert-Qualification ($processes.Count -eq 0) "Qualification-owned processes remain during $Phase`: $detail"
    Add-QualificationEvent -Name 'process_residue_audit' -Status 'passed' -Detail "phase=$Phase; owned_processes=0; exact_paths=true; launch_identity=pid_creation_image; direct_children=parent_lifetime; contract=$($script:qualificationProcessContract)"
}

function Invoke-NativeCommandCapture {
    param(
        [Parameter(Mandatory = $true)][string] $ExecutablePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [ValidateRange(1, 600000)][int] $TimeoutMilliseconds = $script:nativeCommandTimeoutMilliseconds
    )
    Assert-Qualification (Test-Path -LiteralPath $ExecutablePath -PathType Leaf) "Native qualification executable is missing: $ExecutablePath"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $ExecutablePath
    $start.Arguments = (($Arguments | ForEach-Object { Quote-WindowsArgument ([string]$_) }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $previousErrorActionPreference = $ErrorActionPreference
    $started = $false
    $handlePinned = $false
    $processRecord = $null
    $stdoutTask = $null
    $stderrTask = $null
    try {
        $ErrorActionPreference = 'Continue'
        Assert-Qualification ($process.Start()) "Could not start native qualification command: $ExecutablePath"
        $started = $true
        $processHandle = $process.Handle
        Assert-Qualification ($processHandle -ne [IntPtr]::Zero) "Native qualification command returned an invalid process handle: $ExecutablePath"
        $handlePinned = $true
        $processRecord = Register-QualificationProcess -Process $process
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $processId = [uint32]$process.Id
            $terminationError = $null
            try {
                $null = Stop-QualificationProcess -Process $process -HandlePinned $handlePinned
            }
            catch {
                $terminationError = $_.Exception.Message
            }
            $timeoutTasks = [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
            $streamsDrained = [Threading.Tasks.Task]::WaitAll($timeoutTasks, $script:streamDrainTimeoutMilliseconds)
            throw "Native qualification command exceeded its bounded timeout: executable=$ExecutablePath timeout_ms=$TimeoutMilliseconds process_id=$processId streams_drained=$streamsDrained termination_error=$terminationError"
        }
        $streamTasks = [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
        Assert-Qualification ([Threading.Tasks.Task]::WaitAll($streamTasks, $script:streamDrainTimeoutMilliseconds)) "Native qualification command output did not close within the bounded drain deadline: $ExecutablePath"
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $output = @($stdout -split "`r?`n") + @($stderr -split "`r?`n")
        return [pscustomobject]@{
            Output = @($output | Where-Object { $_ -ne '' })
            ExitCode = [int]$process.ExitCode
        }
    }
    finally {
        try {
            $cleanupTerminationError = $null
            if ($started) {
                if (-not $handlePinned -or $null -eq $processRecord) {
                    $script:qualificationProcessRegistrationFailures += "kind=native; image=$ExecutablePath; handle_pinned=$handlePinned; record_present=$($null -ne $processRecord)"
                }
                if ($handlePinned) {
                    try {
                        if (-not $process.HasExited) {
                            $null = Stop-QualificationProcess -Process $process -HandlePinned $handlePinned
                        }
                    }
                    catch {
                        $cleanupTerminationError = $_.Exception.Message
                    }
                }
            }
            if ($null -ne $stdoutTask -and $null -ne $stderrTask) {
                $cleanupTasks = [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
                Assert-Qualification ([Threading.Tasks.Task]::WaitAll($cleanupTasks, $script:streamDrainTimeoutMilliseconds)) "Native qualification command output did not close within the bounded cleanup drain deadline: $ExecutablePath"
            }
            Assert-Qualification ([string]::IsNullOrWhiteSpace($cleanupTerminationError)) "Native qualification process cleanup failed: $cleanupTerminationError"
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
            try {
                if ($null -ne $processRecord) {
                    Complete-QualificationProcess -Record $processRecord -Process $process
                }
            }
            finally {
                $process.Dispose()
            }
        }
    }
}

function ConvertTo-PaperboatStateRelativePath {
    param([Parameter(Mandatory = $true)][string] $Path)
    $rootPath = [IO.Path]::GetFullPath($script:stateRoot).TrimEnd('\')
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
        return ''
    }
    $rootPrefix = $rootPath + '\'
    Assert-Qualification $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) "Paperboat state path escaped the state root: $fullPath"
    return $fullPath.Substring($rootPrefix.Length).Replace('/', '\')
}

function Get-PaperboatStateSecuritySnapshot {
    param([Parameter(Mandatory = $true)][string] $Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $securitySections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
    $ownerSID = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $daclSddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    $securityDescriptor = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]$securitySections)
    Assert-Qualification (-not [string]::IsNullOrWhiteSpace($ownerSID)) "Paperboat state security owner is unavailable: $Path"
    Assert-Qualification (-not [string]::IsNullOrWhiteSpace($daclSddl)) "Paperboat state DACL is unavailable: $Path"
    Assert-Qualification (-not [string]::IsNullOrWhiteSpace($securityDescriptor)) "Paperboat state security descriptor is unavailable: $Path"
    return [pscustomobject]@{
        OwnerSID = $ownerSID
        DaclSddl = $daclSddl
        SecurityDescriptor = $securityDescriptor
    }
}

function New-PaperboatStateSnapshotEntry {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $RelativePath
    )
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    $reparsePoint = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    Assert-Qualification (-not $reparsePoint) "Paperboat state path is a reparse point: $Path"
    $security = Get-PaperboatStateSecuritySnapshot -Path $Path
    $type = if ($item.PSIsContainer) { 'directory' } else { 'file' }
    $sha256 = $null
    $length = $null
    if (-not $item.PSIsContainer) {
        $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToUpperInvariant()
        $length = [int64]$item.Length
    }
    return [pscustomobject]@{
        RelativePath = $RelativePath
        Type = $type
        Attributes = [int64]$item.Attributes
        ReparsePoint = $reparsePoint
        SHA256 = $sha256
        Length = $length
        OwnerSID = $security.OwnerSID
        DaclSddl = $security.DaclSddl
        SecurityDescriptor = $security.SecurityDescriptor
    }
}

function Get-PaperboatStateSnapshot {
    $rootPath = [IO.Path]::GetFullPath($script:stateRoot)
    $rootItem = $null
    try {
        $rootItem = Get-Item -Force -LiteralPath $rootPath -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return [pscustomobject]@{
            RootPresent = $false
            Entries = @()
        }
    }
    Assert-Qualification ($rootItem.PSIsContainer) "Paperboat state root is not a directory: $rootPath"
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($rootPath)
    $entries = @()
    while ($pending.Count -gt 0) {
        $currentPath = $pending.Dequeue()
        $currentItem = Get-Item -Force -LiteralPath $currentPath -ErrorAction Stop
        $relativePath = ConvertTo-PaperboatStateRelativePath -Path $currentPath
        $entries += New-PaperboatStateSnapshotEntry -Path $currentPath -RelativePath $relativePath
        if (-not $currentItem.PSIsContainer) {
            continue
        }
        foreach ($child in @(Get-ChildItem -Force -LiteralPath $currentPath -ErrorAction Stop)) {
            $childPath = [IO.Path]::GetFullPath($child.FullName)
            $null = ConvertTo-PaperboatStateRelativePath -Path $childPath
            $pending.Enqueue($childPath)
        }
    }
    return [pscustomobject]@{
        RootPresent = $true
        Entries = @($entries | Sort-Object -Property RelativePath)
    }
}

function Assert-Preflight {
    Assert-Qualification (Test-Path -LiteralPath $script:msiexec -PathType Leaf) "msiexec.exe is unavailable at $($script:msiexec)."
    Assert-Qualification (Test-Path -LiteralPath $script:icacls -PathType Leaf) "icacls.exe is unavailable at $($script:icacls)."
    Assert-Qualification (Test-Path -LiteralPath $script:serviceControl -PathType Leaf) "sc.exe is unavailable at $($script:serviceControl)."
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
    Assert-Qualification (Test-Path -LiteralPath $resolvedNativeTestExecutable -PathType Leaf) "Native Windows qualification test executable is missing: $resolvedNativeTestExecutable"
    Assert-Qualification ([IO.Path]::GetExtension($resolvedNativeTestExecutable) -ieq '.exe') "Native Windows qualification test executable must be an .exe."
    Assert-QualificationRegularFile -Path $resolvedNativeTestExecutable
    $nativeTestItem = Get-Item -Force -LiteralPath $resolvedNativeTestExecutable -ErrorAction Stop
    $script:nativeTestSHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedNativeTestExecutable -ErrorAction Stop).Hash.ToLowerInvariant()
    $script:nativeTestLength = [int64]$nativeTestItem.Length
    Assert-Qualification ($script:nativeTestLength -gt 0) 'Native Windows qualification test executable is empty.'
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
    Assert-Qualification (@(Get-InstalledPaperboatProducts).Count -eq 0) 'A Paperboat MSI product already exists; refusing to overwrite an unmanaged test state.'
    Assert-NoQualificationProcessResidue -Phase 'preflight'
    Assert-Qualification (@(Get-PaperboatPreviewServices).Count -eq 0) 'A PaperboatPreview-* service already exists; refusing to overwrite an unmanaged test state.'
    if (Test-Path -LiteralPath $script:stateRoot) {
        $stateRootItem = Get-Item -Force -LiteralPath $script:stateRoot -ErrorAction Stop
        Assert-Qualification ($stateRootItem.PSIsContainer) "Paperboat state root is not a directory: $($script:stateRoot)"
        Assert-Qualification ((($stateRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) "Paperboat state root is a reparse point: $($script:stateRoot)"
    }
    Assert-Qualification (@(Get-PaperboatPreviewDeclarations).Count -eq 0) 'A PaperboatPreview-* service declaration already exists; refusing to overwrite an unmanaged test state.'
	Assert-Qualification (-not (Test-Path -LiteralPath $script:openSSHRegistryPath)) "$($script:openSSHRegistryPath) already exists; refusing to run MSI qualification against stale Paperboat OpenSSH ownership state."
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
    $script:preexistingPaperboatState = Get-PaperboatStateSnapshot
    Add-QualificationEvent -Name 'preexisting_state_snapshot' -Status 'passed' -Detail "root_present=$($script:preexistingPaperboatState.RootPresent); entries=$(@($script:preexistingPaperboatState.Entries).Count); security=owner_dacl_descriptor; reparse=false"
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
        $roleProbe = Invoke-NativeCommandCapture -ExecutablePath $rolePath -Arguments $roleArguments
        $output = @($roleProbe.Output)
        $exitCode = $roleProbe.ExitCode
        Assert-Qualification ($exitCode -eq 2) "$($probe.File) accepted forbidden command '$($probe.Arguments -join ' ')' or returned exit code $exitCode instead of 2: $($output -join ' ')"
        Assert-Qualification (($output -join ' ') -match 'service artifact cannot run that command') "$($probe.File) did not report the role allowlist rejection: $($output -join ' ')"
    }
    Add-QualificationEvent -Name 'role_artifact_allowlist' -Status 'passed' -Detail "version=$ExpectedVersion; runtime_cli_rejected=true; hostd_cli_rejected=true; updater_worker_rejected=true"
    $cliTarget = Join-Path $script:installRoot 'releases\cli-current\pb.exe'
    Assert-Qualification (Test-Path -LiteralPath $cliTarget -PathType Leaf) "Stable CLI target is missing $cliTarget."
    $launcherResult = Invoke-NativeCommandCapture -ExecutablePath (Join-Path $script:binaryRoot 'pb.exe') -Arguments @('--version')
    $launcherOutput = @($launcherResult.Output)
    $launcherExitCode = $launcherResult.ExitCode
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
    if ($Phase -eq 'uninstall') {
        Assert-Qualification (-not (Test-Path -LiteralPath $script:openSSHRegistryPath)) "Paperboat OpenSSH ownership marker remains after MSI ${Phase}: $($script:openSSHRegistryPath)"
    }
    Add-QualificationEvent -Name 'openssh_isolation' -Status 'passed' -Detail "phase=$Phase; service_absent=true; marker_absent=$(-not (Test-Path -LiteralPath $script:openSSHRegistryPath))"
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

function Assert-PaperboatStateSnapshotEntryUnchanged {
    param(
        [Parameter(Mandatory = $true)][psobject] $Baseline,
        [Parameter(Mandatory = $true)][psobject] $Current
    )
    $path = if ($Baseline.RelativePath -eq '') { $script:stateRoot } else { Join-Path $script:stateRoot $Baseline.RelativePath }
    Assert-Qualification ($Current.Type -eq $Baseline.Type) "Pre-existing Paperboat state type changed: $path"
    Assert-Qualification ([int64]$Current.Attributes -eq [int64]$Baseline.Attributes) "Pre-existing Paperboat state attributes changed: $path"
    Assert-Qualification ($Current.ReparsePoint -eq $Baseline.ReparsePoint -and -not $Current.ReparsePoint) "Pre-existing Paperboat state reparse status changed: $path"
    Assert-Qualification ($Current.SHA256 -ceq $Baseline.SHA256) "Pre-existing Paperboat state SHA256 changed: $path"
    Assert-Qualification ($Current.Length -eq $Baseline.Length) "Pre-existing Paperboat state length changed: $path"
    Assert-Qualification ($Current.OwnerSID -ceq $Baseline.OwnerSID) "Pre-existing Paperboat state owner changed: $path"
    Assert-Qualification ($Current.DaclSddl -ceq $Baseline.DaclSddl) "Pre-existing Paperboat state DACL changed: $path"
    Assert-Qualification ($Current.SecurityDescriptor -ceq $Baseline.SecurityDescriptor) "Pre-existing Paperboat state security descriptor changed: $path"
}

function Assert-PaperboatStateResidue {
    Assert-Qualification ($null -ne $script:preexistingPaperboatState) 'Pre-existing Paperboat state was not snapshotted before MSI mutation.'
    $baseline = $script:preexistingPaperboatState
    $current = Get-PaperboatStateSnapshot
    Assert-Qualification ($current.RootPresent -eq $baseline.RootPresent) "Paperboat state root presence changed after uninstall: baseline=$($baseline.RootPresent) current=$($current.RootPresent)"
    $baselineEntries = @($baseline.Entries)
    $currentEntries = @($current.Entries)
    $baselineByPath = @{}
    foreach ($entry in $baselineEntries) {
        $baselineByPath[$entry.RelativePath] = $entry
    }
    $currentByPath = @{}
    foreach ($entry in $currentEntries) {
        $currentByPath[$entry.RelativePath] = $entry
    }

    foreach ($baselineEntry in $baselineEntries) {
        Assert-Qualification ($currentByPath.ContainsKey($baselineEntry.RelativePath)) "Pre-existing Paperboat state disappeared after uninstall: $($baselineEntry.RelativePath)"
        Assert-PaperboatStateSnapshotEntryUnchanged -Baseline $baselineEntry -Current $currentByPath[$baselineEntry.RelativePath]
    }

    # These are the only directories that WiX or this qualification creates as
    # empty placeholders. Any file or unlisted descendant is new residue.
    $allowedNewEmptyOwnedDirectories = @(
        'ssh',
        'updates',
        'updates\current',
        'updates\rollback',
        'logs',
        'services',
        'previews',
        'previews\active'
    )
    foreach ($currentEntry in $currentEntries) {
        if ($baselineByPath.ContainsKey($currentEntry.RelativePath) -or $currentEntry.RelativePath -eq '') {
            continue
        }
        $relativeLower = $currentEntry.RelativePath.ToLowerInvariant()
        Assert-Qualification ($relativeLower -in $allowedNewEmptyOwnedDirectories) "Unknown Paperboat state residue remains after uninstall: $($currentEntry.RelativePath)"
        Assert-Qualification ($currentEntry.Type -eq 'directory') "New Paperboat state residue is not an empty owned directory placeholder: $($currentEntry.RelativePath)"
        Assert-Qualification (-not $currentEntry.ReparsePoint) "New Paperboat state placeholder is a reparse point: $($currentEntry.RelativePath)"
    }
}

function Assert-Uninstalled {
    $services = Get-PaperboatServices
    Assert-Qualification ($services.Count -eq 0) "Paperboat SCM services remain after uninstall: $($services.Name -join ', ')."
    $previewServices = Get-PaperboatPreviewServices
    Assert-Qualification ($previewServices.Count -eq 0) "PaperboatPreview-* services remain after uninstall: $($previewServices.Name -join ', ')."
	foreach ($definitionName in @('PaperboatHostd.json', 'PaperboatUpdated.json')) {
		$definitionPath = Join-Path $script:stateRoot "services\$definitionName"
		Assert-Qualification (-not (Test-Path -LiteralPath $definitionPath)) "Fixed Paperboat service declaration remains after uninstall: $definitionPath"
	}
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
    Assert-PaperboatStateResidue
    Assert-PaperboatSshdAbsent -Phase 'uninstall'
    Assert-Qualification (@(Get-InstalledPaperboatProducts).Count -eq 0) 'An ARP Paperboat product entry remains after uninstall.'
    $machinePathEntries = @(Get-MachinePathEntries)
    $expectedPathEntry = ConvertTo-NormalizedMachinePathEntry $script:binaryRoot
    $paperboatPathEntryCount = @($machinePathEntries | Where-Object { $_ -ieq $expectedPathEntry }).Count
    Assert-Qualification ($paperboatPathEntryCount -eq 0) "Paperboat bin remains in the machine PATH after uninstall; found $paperboatPathEntryCount normalized entries for $expectedPathEntry."
    Assert-NoQualificationProcessResidue -Phase 'uninstall'
    Add-QualificationEvent -Name 'msi_uninstall_assertions' -Status 'passed' -Detail 'fixed services, dynamic preview services, process residue, PATH ownership, PaperboatSshd preflight absence, binaries, product registry, ARP entry, and provisioning metadata were verified.'
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
    $nativeTestArguments = @('-test.v', '-test.run', $RunPattern, '-test.count', '1', '-test.timeout', $Timeout)
    return Invoke-NativeTestPattern -ExecutablePath $resolvedNativeTestExecutable -Arguments $nativeTestArguments -RunPattern $RunPattern -Description $Description -EvidenceName $Description
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
            $preMsiEvidence = Invoke-NativeGoTests -RunPattern $preMsiRunPattern -Description 'pre-MSI native tests' -Timeout '5m'
            Add-QualificationEvent -Name 'native_go_e2e' -Status 'passed' -Detail "pre-MSI SCM hostd/updater, ConPTY, and long-path tests; tests_run=$($preMsiEvidence.TestsRunCount); evidence=$($preMsiEvidence.EvidencePath)"

            try {
                Stage-PreMsiRuntimeCurrentFixture
                Assert-PreMsiRuntimeCurrentFixtureIntegrity
                Add-QualificationEvent -Name 'native_go_preview_e2e' -Status 'started' -Detail 'durable preview service against hash-bound RuntimeCurrent fixture'
                $previewEvidence = Invoke-NativeGoTests -RunPattern '^TestNativeDurablePreviewServiceLifecycle$' -Description 'durable preview RuntimeCurrent test' -Timeout '5m'
                Add-QualificationEvent -Name 'native_go_preview_e2e' -Status 'passed' -Detail "durable preview service against hash-bound RuntimeCurrent fixture; tests_run=$($previewEvidence.TestsRunCount); evidence=$($previewEvidence.EvidencePath)"
            }
            finally {
                Remove-PreMsiRuntimeCurrentFixture
            }

            Add-QualificationEvent -Name 'native_msi_cleanup' -Status 'started' -Detail 'runtime-current PaperboatPreview ownership and bounded slot cleanup'
			$cleanupArguments = @('-test.v', '-test.run', '^TestNativeMSIPreview', '-test.count', '1', '-test.timeout', '2m')
			$cleanupEvidence = Invoke-NativeTestPattern -ExecutablePath $resolvedMsiCleanupTestExecutable -Arguments $cleanupArguments -RunPattern '^TestNativeMSIPreview' -Description 'MSI preview cleanup tests' -EvidenceName 'msi-preview-cleanup'
			Add-QualificationEvent -Name 'native_msi_cleanup' -Status 'passed' -Detail "runtime-current service/declaration removal and ownership-conflict preservation cases passed; tests_run=$($cleanupEvidence.TestsRunCount); evidence=$($cleanupEvidence.EvidencePath)"
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
        [Parameter(Mandatory = $true)][string] $ExecutablePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $RunPattern,
        [Parameter(Mandatory = $true)][string] $EvidenceName,
        [Parameter(Mandatory = $true)][Security.SecureString] $CredentialSecret,
        [Parameter(Mandatory = $true)][string] $OwnerAccount,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [Parameter(Mandatory = $true)][string] $StandardOutputPath,
        [Parameter(Mandatory = $true)][string] $StandardErrorPath
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $ExecutablePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.Arguments = (($Arguments | ForEach-Object { Quote-WindowsArgument ([string]$_) }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $accountSeparator = $OwnerAccount.IndexOf('\')
    Assert-Qualification ($accountSeparator -gt 0 -and $accountSeparator -lt ($OwnerAccount.Length - 1)) 'Qualification owner account must be DOMAIN\user.'
    $start.Domain = $OwnerAccount.Substring(0, $accountSeparator)
    $start.UserName = $OwnerAccount.Substring($accountSeparator + 1)
    $passwordProperty = 'Pass' + 'word'
    $start.$passwordProperty = $CredentialSecret
    $start.LoadUserProfile = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    $handlePinned = $false
    $processRecord = $null
    $stdoutTask = $null
    $stderrTask = $null
    $ownerActionStage = 'unreported'
    $ownerCleanupStage = 'not-started'
    $ownerCleanupFailure = 'none'
    $primaryException = $null
    $cleanupFailureKinds = @()
    $result = $null
    try {
        Assert-Qualification ($process.Start()) 'Could not start the owner-account qualification process.'
        $started = $true
        $processHandle = $process.Handle
        Assert-Qualification ($processHandle -ne [IntPtr]::Zero) 'Owner-account qualification returned an invalid process handle.'
        $handlePinned = $true
        $processRecord = Register-QualificationProcess -Process $process
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $exited = $process.WaitForExit(90000)
        if (-not $exited) {
            $stopSucceeded = $true
            if ($handlePinned) {
                try {
                    $null = Stop-QualificationProcess -Process $process -HandlePinned $handlePinned
                }
                catch {
                    $stopSucceeded = $false
                }
            }
            $stdoutDrained = $false
            $stderrDrained = $false
            try { $stdoutDrained = $stdoutTask.Wait($script:streamDrainTimeoutMilliseconds) } catch { $stdoutDrained = $false }
            try { $stderrDrained = $stderrTask.Wait($script:streamDrainTimeoutMilliseconds) } catch { $stderrDrained = $false }
            if ($stdoutDrained) {
                $timeoutStages = Get-OwnerQualificationStages -Output $stdoutTask.GetAwaiter().GetResult()
                $ownerActionStage = $timeoutStages.ActionStage
                $ownerCleanupStage = $timeoutStages.CleanupStage
                $ownerCleanupFailure = $timeoutStages.CleanupFailure
            }
            Assert-Qualification $false "Owner-account qualification process exceeded its 90 second deadline; action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage; cleanup_failure=$ownerCleanupFailure; stop_succeeded=$stopSucceeded; stdout_drained=$stdoutDrained; stderr_drained=$stderrDrained."
        }
        $streamTasks = [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
        Assert-Qualification ([Threading.Tasks.Task]::WaitAll($streamTasks, $script:streamDrainTimeoutMilliseconds)) 'Owner-account qualification output did not close within the bounded drain deadline.'
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $ownerStages = Get-OwnerQualificationStages -Output $stdout
        $ownerActionStage = $ownerStages.ActionStage
        $ownerCleanupStage = $ownerStages.CleanupStage
        $ownerCleanupFailure = $ownerStages.CleanupFailure
        [IO.File]::WriteAllText($StandardOutputPath, $stdout)
        [IO.File]::WriteAllText($StandardErrorPath, $stderr)
        $ownerOutput = @($stdout -split "`r?`n") + @($stderr -split "`r?`n")
        $evidence = New-NativeTestExecutionEvidence -ExecutablePath $ExecutablePath -Arguments $Arguments -RunPattern $RunPattern -Description $EvidenceName -EvidenceName $EvidenceName -ExitCode $process.ExitCode -Output $ownerOutput
        if ($process.ExitCode -ne 0) {
            Assert-Qualification $false "Native Windows qualification test pattern failed for $EvidenceName with exit code $($process.ExitCode); action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage; cleanup_failure=$ownerCleanupFailure. Evidence: $($evidence.EvidencePath)."
        }
        Assert-NativeTestExecutionEvidence -Evidence $evidence -Description $EvidenceName
        $result = [pscustomobject]@{ ExitCode = $process.ExitCode; Output = @($stdout, $stderr) -join "`n"; Evidence = $evidence }
    }
    catch {
        $primaryException = $_
    }
    finally {
        try {
            $cleanupTerminationError = $null
            if ($started) {
                if (-not $handlePinned -or $null -eq $processRecord) {
                    $script:qualificationProcessRegistrationFailures += "kind=owner; image=$ExecutablePath; handle_pinned=$handlePinned; record_present=$($null -ne $processRecord)"
                    $cleanupFailureKinds += 'registration'
                }
                if ($handlePinned) {
                    try {
                        if (-not $process.HasExited) {
                            $null = Stop-QualificationProcess -Process $process -HandlePinned $handlePinned
                        }
                    }
                    catch {
                        $cleanupTerminationError = $_.Exception.Message
                        $cleanupFailureKinds += 'termination'
                    }
                }
            }
            if ($null -ne $stdoutTask -and $null -ne $stderrTask) {
                $cleanupTasks = [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
                $cleanupDrained = $false
                try {
                    $cleanupDrained = [Threading.Tasks.Task]::WaitAll($cleanupTasks, $script:streamDrainTimeoutMilliseconds)
                }
                catch {
                    $cleanupDrained = $false
                }
                if (-not $cleanupDrained) {
                    $script:qualificationProcessRegistrationFailures += "kind=owner; cleanup_drain=false; action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage"
                    $cleanupFailureKinds += 'stream-drain'
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($cleanupTerminationError)) {
                $script:qualificationProcessRegistrationFailures += "kind=owner; cleanup_termination=false; action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage"
            }
        }
        catch {
            $cleanupFailureKinds += 'cleanup-unexpected'
            $script:qualificationProcessRegistrationFailures += "kind=owner; cleanup_unexpected=false; action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage"
        }
        finally {
            try {
                if ($null -ne $processRecord) {
                    try {
                        Complete-QualificationProcess -Record $processRecord -Process $process
                    }
                    catch {
                        $cleanupFailureKinds += 'completion'
                        $script:qualificationProcessRegistrationFailures += "kind=owner; completion=false; action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage"
                    }
                }
            }
            finally {
                try {
                    $process.Dispose()
                }
                catch {
                    $cleanupFailureKinds += 'dispose'
                    $script:qualificationProcessRegistrationFailures += "kind=owner; dispose=false; action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage"
                }
            }
        }
    }
    if ($null -ne $primaryException) {
        throw $primaryException
    }
    Assert-Qualification ($cleanupFailureKinds.Count -eq 0) "Owner-account process cleanup failed; kinds=$($cleanupFailureKinds -join ','); action_stage=$ownerActionStage; cleanup_stage=$ownerCleanupStage; cleanup_failure=$ownerCleanupFailure."
    return $result
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
    $qualificationOwnerTest = Join-Path $qualificationRoot 'paperboat-windows-s4u-owner.test.exe'
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
        $qualificationACLResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($qualificationRoot, '/inheritance:r', '/grant:r', "*${ownerSID}:(OI)(CI)RX", '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
        Assert-Qualification ($qualificationACLResult.ExitCode -eq 0) "Could not protect the S4U qualification root directory: $($qualificationACLResult.Output -join ' ')"
        $qualificationOwnerResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($qualificationRoot, '/setowner', '*S-1-5-32-544')
        Assert-Qualification ($qualificationOwnerResult.ExitCode -eq 0) "Could not set the trusted owner on the S4U qualification root directory: $($qualificationOwnerResult.Output -join ' ')"
        Assert-QualificationTransactionDirectory -Path $qualificationRoot -OwnerSID $ownerSID -OwnerWritable $false
        Copy-Item -LiteralPath $resolvedS4UTestExecutable -Destination $qualificationOwnerTest -Force
        Assert-Qualification (Test-Path -LiteralPath $qualificationOwnerTest -PathType Leaf) 'S4U owner test executable was not isolated in the qualification root.'
        Assert-Qualification (((Get-Item -Force -LiteralPath $qualificationOwnerTest).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable is a reparse point.'
        $ownerTestACLResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($qualificationOwnerTest, '/inheritance:r', '/grant:r', "*${ownerSID}:RX", '*S-1-5-18:F', '*S-1-5-32-544:F')
        Assert-Qualification ($ownerTestACLResult.ExitCode -eq 0) "Could not protect the S4U owner test executable: $($ownerTestACLResult.Output -join ' ')"
        $ownerTestOwnerResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($qualificationOwnerTest, '/setowner', '*S-1-5-32-544')
        Assert-Qualification ($ownerTestOwnerResult.ExitCode -eq 0) "Could not set the trusted owner on the S4U owner test executable: $($ownerTestOwnerResult.Output -join ' ')"
        $ownerTestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $qualificationOwnerTest).Hash.ToLowerInvariant()
        Assert-Qualification ($ownerTestHash -eq (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant()) 'Isolated S4U owner test executable differs from its source.'
        New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
        Assert-Qualification (((Get-Item -Force -LiteralPath $workRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Owner-writable S4U work directory is a reparse point.'
        $workACLResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($workRoot, '/inheritance:r', '/grant:r', "*${ownerSID}:(OI)(CI)M", '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
        Assert-Qualification ($workACLResult.ExitCode -eq 0) "Could not protect the owner-writable S4U work directory: $($workACLResult.Output -join ' ')"
        $workOwnerResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($workRoot, '/setowner', '*S-1-5-32-544')
        Assert-Qualification ($workOwnerResult.ExitCode -eq 0) "Could not set the trusted owner on the owner-writable S4U work directory: $($workOwnerResult.Output -join ' ')"
        Assert-QualificationTransactionDirectory -Path $workRoot -OwnerSID $ownerSID -OwnerWritable $true
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U test executable source is a reparse point.'
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UFixturePath).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U fixture source is a reparse point.'
        $sourcePreparationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant()
        $sourceFixtureHashBeforePreparation = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UFixturePath).Hash.ToLowerInvariant()
        $env:PAPERBOAT_WINDOWS_E2E_S4U_OWNER_SID = $ownerSID
        $env:PAPERBOAT_WINDOWS_E2E_S4U_REPORT_PATH = $reportPath
        $env:PAPERBOAT_WINDOWS_E2E_S4U_SERVICE_NAME = $serviceName
        $prepareArguments = @('-test.v', '-test.run', '^TestNativePrepareS4UDPAPIQualification$', '-test.count', '1', '-test.timeout', '1m', '-paperboat-owner-sid', $ownerSID, '-paperboat-report-path', $reportPath)
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point before owner-context preparation.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed immediately before owner-context preparation.'
        $prepare = Invoke-OwnerQualificationTest -ExecutablePath $qualificationOwnerTest -Arguments $prepareArguments -RunPattern '^TestNativePrepareS4UDPAPIQualification$' -EvidenceName 's4u-owner-prepare' -CredentialSecret $credentialSecret -OwnerAccount "$env:COMPUTERNAME\$ownerName" -WorkingDirectory $workRoot -StandardOutputPath $prepareStdout -StandardErrorPath $prepareStderr
        Assert-Qualification (Test-Path -LiteralPath $prepareStdout -PathType Leaf) 'Owner preparation stdout redirect was not created in the qualification directory.'
        Assert-Qualification (Test-Path -LiteralPath $prepareStderr -PathType Leaf) 'Owner preparation stderr redirect was not created in the qualification directory.'
        if ($prepare.ExitCode -ne 0) {
            throw "Owner-context Credential Manager migration preparation failed with exit code $($prepare.ExitCode): $($prepare.Output)"
        }

        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point during owner-context preparation.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed during owner-context preparation.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $qualificationOwnerTest).Hash.ToLowerInvariant() -eq $ownerTestHash) 'Isolated S4U owner test executable changed during owner-context preparation.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UFixturePath).Hash.ToLowerInvariant() -eq $sourceFixtureHashBeforePreparation) 'S4U fixture source changed during owner-context preparation.'
        Assert-QualificationAncestorTrusted $programDataRoot
        Assert-QualificationAncestorTrusted $qualificationParent
        Assert-QualificationTransactionDirectory -Path $qualificationRoot -OwnerSID $ownerSID -OwnerWritable $false
        Assert-QualificationTransactionDirectory -Path $workRoot -OwnerSID $ownerSID -OwnerWritable $true
        New-Item -ItemType Directory -Force -Path $trustedRoot | Out-Null
        $trustedACLResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($trustedRoot, '/inheritance:r', '/grant:r', "*${ownerSID}:(OI)(CI)RX", '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
        Assert-Qualification ($trustedACLResult.ExitCode -eq 0) "Could not protect the trusted S4U fixture directory: $($trustedACLResult.Output -join ' ')"
        $trustedOwnerResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($trustedRoot, '/setowner', '*S-1-5-32-544')
        Assert-Qualification ($trustedOwnerResult.ExitCode -eq 0) "Could not set the trusted owner on the trusted S4U fixture directory: $($trustedOwnerResult.Output -join ' ')"
        Assert-QualificationTransactionDirectory -Path $trustedRoot -OwnerSID $ownerSID -OwnerWritable $false
        Assert-Qualification (((Get-Item -Force -LiteralPath $trustedRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Trusted S4U fixture directory is a reparse point.'
        Copy-Item -LiteralPath $resolvedS4UFixturePath -Destination $qualificationFixture -Force
        Assert-Qualification (Test-Path -LiteralPath $qualificationFixture -PathType Leaf) 'S4U fixture executable was not isolated in the trusted directory.'
        Assert-Qualification (((Get-Item -Force -LiteralPath $qualificationFixture).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U fixture executable is a reparse point.'
        $fixtureACLResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($qualificationFixture, '/inheritance:r', '/grant:r', "*${ownerSID}:RX", '*S-1-5-18:F', '*S-1-5-32-544:F')
        Assert-Qualification ($fixtureACLResult.ExitCode -eq 0) "Could not protect the trusted S4U fixture executable: $($fixtureACLResult.Output -join ' ')"
        $fixtureOwnerResult = Invoke-NativeCommandCapture -ExecutablePath $script:icacls -Arguments @($qualificationFixture, '/setowner', '*S-1-5-32-544')
        Assert-Qualification ($fixtureOwnerResult.ExitCode -eq 0) "Could not set the trusted owner on the S4U fixture executable: $($fixtureOwnerResult.Output -join ' ')"
        $trustedFixtureHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $qualificationFixture).Hash.ToLowerInvariant()
        Assert-Qualification ($trustedFixtureHash -eq $sourceFixtureHashBeforePreparation) 'Trusted S4U fixture differs from its source.'
        $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE = $qualificationFixture
        $env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE_SHA256 = $trustedFixtureHash

        $mutationArguments = @('-test.v', '-test.run', '^TestNativeOwnerCannotMutateS4UFixture$', '-test.count', '1', '-test.timeout', '1m', '-paperboat-owner-sid', $ownerSID, '-paperboat-fixture-path', $qualificationFixture, '-paperboat-fixture-sha256', $trustedFixtureHash)
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point before owner immutability probe.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed immediately before owner immutability probe.'
        $mutation = Invoke-OwnerQualificationTest -ExecutablePath $qualificationOwnerTest -Arguments $mutationArguments -RunPattern '^TestNativeOwnerCannotMutateS4UFixture$' -EvidenceName 's4u-owner-mutation' -CredentialSecret $credentialSecret -OwnerAccount "$env:COMPUTERNAME\$ownerName" -WorkingDirectory $workRoot -StandardOutputPath $mutationStdout -StandardErrorPath $mutationStderr
        Assert-Qualification (Test-Path -LiteralPath $mutationStdout -PathType Leaf) 'Owner mutation-probe stdout redirect was not created in the work directory.'
        Assert-Qualification (Test-Path -LiteralPath $mutationStderr -PathType Leaf) 'Owner mutation-probe stderr redirect was not created in the work directory.'
        if ($mutation.ExitCode -ne 0) {
            throw "Owner fixture immutability probe failed with exit code $($mutation.ExitCode): $($mutation.Output)"
        }
        Assert-Qualification (((Get-Item -Force -LiteralPath $resolvedS4UTestExecutable).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'S4U owner test executable became a reparse point during owner immutability probe.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedS4UTestExecutable).Hash.ToLowerInvariant() -eq $sourcePreparationHash) 'S4U owner test executable changed during owner immutability probe.'
        Assert-Qualification ((Get-FileHash -Algorithm SHA256 -LiteralPath $qualificationOwnerTest).Hash.ToLowerInvariant() -eq $ownerTestHash) 'Isolated S4U owner test executable changed during owner immutability probe.'
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
        $loggedOutEvidence = Invoke-NativeTestPattern -ExecutablePath $resolvedS4UTestExecutable -Arguments $arguments -RunPattern '^TestNativeLoggedOutS4UDPAPIQualification$' -Description 'logged-out S4U DPAPI qualification' -EvidenceName 's4u-logged-out'
        Add-QualificationEvent -Name 'native_s4u_dpapi' -Status 'passed' -Detail "owner_sid=$ownerSID; architecture=$Architecture; dpapi_readable=true; credential_manager_migration=true; tests_run=$($loggedOutEvidence.TestsRunCount); evidence=$($loggedOutEvidence.EvidencePath); owner_prepare_evidence=$($prepare.Evidence.EvidencePath); owner_mutation_evidence=$($mutation.Evidence.EvidencePath)"
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
                $deleteResult = Invoke-NativeCommandCapture -ExecutablePath $script:serviceControl -Arguments @('delete', $serviceName)
                if ($deleteResult.ExitCode -ne 0) {
                    throw "sc.exe delete returned exit code $($deleteResult.ExitCode): $($deleteResult.Output -join ' ')"
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
    $evidence = Invoke-NativeTestPattern -ExecutablePath $resolvedHostinstallTestExecutable -Arguments $arguments -RunPattern '^TestNativeLegacyOwnerFullSecurityMigration$' -Description 'legacy Windows security migration qualification' -EvidenceName 'legacy-security-migration'
    Add-QualificationEvent -Name 'native_legacy_security_migration' -Status 'passed' -Detail "owner_full_rejected_before=true; owner_read_only_after=true; config_unchanged=true; tests_run=$($evidence.TestsRunCount); evidence=$($evidence.EvidencePath)"
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
        native_test_sha256 = $script:nativeTestSHA256
        native_test_length = $script:nativeTestLength
        events = $script:events
        failure = if ($Failure -eq '') { $null } else { $Failure }
    }
    $reportJSON = $report | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($reportPath, $reportJSON + "`n", [Text.UTF8Encoding]::new($false))
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
    $script:preflightPassed = $true
    Invoke-S4UDPAPIQualification
    Invoke-LegacySecurityMigrationQualification
    Invoke-GoQualification
    Stage-MsiPathFixtures

    $freshLog = Join-Path $resolvedOutputDirectory 'msi-fresh.log'
    Invoke-Msi -Arguments @('/i', (Quote-WindowsArgument $script:qualifiedFreshMsiPath)) -LogPath $freshLog -Operation 'fresh_install'
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
    Assert-Uninstalled

    $reinstallLog = Join-Path $resolvedOutputDirectory 'msi-reinstall.log'
    Invoke-Msi -Arguments @('/i', (Quote-WindowsArgument $script:qualifiedFreshMsiPath)) -LogPath $reinstallLog -Operation 'reinstall'
    Assert-InstalledPayload -ExpectedVersion $Version
    $reinstallEntries = @(Get-InstalledPaperboatProducts)
    Assert-Qualification ($reinstallEntries.Count -eq 1) "Expected one ARP entry after reinstall, found $($reinstallEntries.Count)."
    $reinstallUninstallLog = Join-Path $resolvedOutputDirectory 'msi-reinstall-uninstall.log'
    Invoke-Msi -Arguments @('/x', $reinstallEntries[0].PSChildName) -LogPath $reinstallUninstallLog -Operation 'reinstall_uninstall'
    Assert-Uninstalled
    Add-QualificationEvent -Name 'msi_reinstall_assertions' -Status 'passed' -Detail 'clean reinstall and second uninstall passed from a path containing spaces and Unicode'
}
catch {
    $failure = $_.Exception.Message
    Add-QualificationEvent -Name 'qualification' -Status 'failed' -Detail $failure
    $bodyFailure = $_
}
finally {
    if ($script:preflightPassed) {
        try {
            $entries = @(Get-InstalledPaperboatProducts)
            if ($entries.Count -gt 0) {
                Assert-Qualification ($entries.Count -eq 1) "Failure cleanup found multiple Paperboat MSI products: $($entries.PSChildName -join ', ')."
                $cleanupCode = $entries[0].PSChildName
                $cleanupLog = Join-Path $resolvedOutputDirectory 'msi-cleanup.log'
                Invoke-Msi -Arguments @('/x', $cleanupCode) -LogPath $cleanupLog -Operation 'failure_cleanup'
            }
            Assert-NoQualificationProcessResidue -Phase 'final_cleanup'
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
