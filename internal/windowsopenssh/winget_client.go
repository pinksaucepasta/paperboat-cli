package windowsopenssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const approvedWinGetModuleVersion = "1.9.25190"

func powershell7Command() string {
	if configured := strings.TrimSpace(os.Getenv("PAPERBOAT_PWSH_PATH")); configured != "" {
		if _, err := os.Stat(configured); err == nil {
			return configured
		}
	}
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	for _, candidate := range []string{
		filepath.Join(programFiles, "PowerShell", "7", "pwsh.exe"),
		filepath.Join(programFiles, "PowerShell", "7-preview", "pwsh.exe"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "pwsh.exe"
}

// ensureSystemWingetModule installs and verifies Microsoft's pinned WinGet
// PowerShell client. Microsoft explicitly does not support winget.exe under
// LocalSystem; this module is its supported machine-wide system-context API.
func ensureSystemWingetModule(ctx context.Context, runner Runner) error {
	moduleCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"$required='" + approvedWinGetModuleVersion + "'",
		"$module=Get-Module -ListAvailable -Name Microsoft.WinGet.Client|Where-Object {$_.Version.ToString()-eq $required}|Select-Object -First 1",
		"if($null-eq $module){[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope AllUsers -Force|Out-Null;Install-Module -Name Microsoft.WinGet.Client -RequiredVersion $required -Repository PSGallery -Scope AllUsers -Force -AllowClobber; $module=Get-Module -ListAvailable -Name Microsoft.WinGet.Client|Where-Object {$_.Version.ToString()-eq $required}|Select-Object -First 1}",
		"if($null-eq $module){throw 'Pinned Microsoft.WinGet.Client module is unavailable'}",
		// The Microsoft module ships open-source dependency DLLs which are
		// intentionally not Authenticode-signed. Verify the module's primary
		// Microsoft assembly, not every transitive dependency.
		"$dlls=@(Get-ChildItem -LiteralPath $module.ModuleBase -Filter 'Microsoft.WinGet.Client.Cmdlets.dll' -File -Recurse)",
		"if($dlls.Count-eq 0){throw 'Microsoft.WinGet.Client primary assembly is missing'}",
		securityModuleImport,
		"foreach($dll in $dlls){$signature=Get-AuthenticodeSignature -LiteralPath $dll.FullName;if($signature.Status-ne 'Valid'-or $signature.SignerCertificate.Subject-notlike '*Microsoft*'){throw ('Untrusted WinGet module assembly: '+$dll.FullName)}}",
		"Import-Module -Name $module.Path -Force -ErrorAction Stop",
		"if($null-eq (Get-Command Install-WinGetPackage -ErrorAction SilentlyContinue)){throw 'Install-WinGetPackage is unavailable'}",
		"Write-Output $module.Version.ToString()",
	}, ";")
	output, err := runner.Run(moduleCtx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil || strings.TrimSpace(string(output)) != approvedWinGetModuleVersion {
		return errors.Join(ErrInstallerUnavailable, fmt.Errorf("WinGet system client: %s", boundedOutput(output)), err)
	}
	return nil
}

func installWithSystemWinget(ctx context.Context, config Config, force bool) error {
	if err := ensureSystemWingetModule(ctx, config.Runner); err != nil {
		return err
	}
	installCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	forceArgument := ""
	if force {
		forceArgument = " -Force"
	}
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"Import-Module Microsoft.WinGet.Client -RequiredVersion " + approvedWinGetModuleVersion + " -Force",
		"Remove-WinGetSource -Name winget -ErrorAction SilentlyContinue|Out-Null;Add-WinGetSource -Name winget -Argument 'https://cdn.winget.microsoft.com/cache' -Type Microsoft.PreIndexed.Package -TrustLevel Trusted -ErrorAction Stop|Out-Null",
		"$result=Install-WinGetPackage -Id '" + PackageID + "' -MatchOption Equals -Version '" + config.ApprovedVersion + "' -Source winget -Scope System -Mode Silent" + forceArgument + " -Confirm:$false -ErrorAction Stop",
		"if($null-eq $result){throw 'WinGet returned no installation result'}",
		"$result|ConvertTo-Json -Compress -Depth 4",
	}, ";")
	output, err := config.Runner.Run(installCtx, powershell7Command(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInstallFailed, boundedOutput(output))
	}
	return nil
}
