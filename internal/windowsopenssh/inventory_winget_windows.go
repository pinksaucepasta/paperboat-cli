//go:build windows

package windowsopenssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func inventoryWithSystemWinget(ctx context.Context, runner Runner) (bool, string, error) {
	if err := ensureSystemWingetModule(ctx, runner); err != nil {
		return false, "", err
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"Import-Module Microsoft.WinGet.Client -RequiredVersion " + approvedWinGetModuleVersion + " -Force",
		"Remove-WinGetSource -Name winget -ErrorAction SilentlyContinue|Out-Null;Add-WinGetSource -Name winget -Argument 'https://cdn.winget.microsoft.com/cache' -Type Microsoft.PreIndexed.Package -TrustLevel Trusted -ErrorAction Stop|Out-Null",
		"$package=Get-WinGetPackage -Id '" + PackageID + "' -MatchOption Equals -ErrorAction Stop|Select-Object -First 1",
		"if($null-eq $package){[pscustomobject]@{installed=$false;version=''}|ConvertTo-Json -Compress}else{[pscustomobject]@{installed=$true;version=[string]$package.InstalledVersion}|ConvertTo-Json -Compress}",
	}, ";")
	output, err := runner.Run(queryCtx, powershell7Command(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return false, "", errors.Join(ErrInstallerUnavailable, fmt.Errorf("WinGet package inventory: %s", boundedOutput(output)), err)
	}
	var inventory struct {
		Installed bool   `json:"installed"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(output, &inventory); err != nil {
		return false, "", errors.Join(ErrInstallerUnavailable, fmt.Errorf("decode WinGet package inventory: %w", err))
	}
	return inventory.Installed, strings.TrimSpace(inventory.Version), nil
}
