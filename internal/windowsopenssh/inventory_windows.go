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

func collectInventory(ctx context.Context, config Config) (InventoryRecord, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	script := inventoryPowerShell(config)
	output, err := config.Runner.Run(probeCtx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cancel()
	if err != nil {
		return InventoryRecord{}, fmt.Errorf("inventory OpenSSH: %w", errors.New(boundedOutput(output)))
	}
	var record InventoryRecord
	if err := json.Unmarshal(output, &record); err != nil {
		return InventoryRecord{}, fmt.Errorf("decode OpenSSH inventory: %w", err)
	}
	// Resolve only the registered Microsoft-signed App Installer executable. Do
	// not inspect package registration by running a PATH-resolved winget.exe.
	resolveCtx, resolveCancel := context.WithTimeout(ctx, 15*time.Second)
	wingetPath, resolveErr := resolveWinget(resolveCtx, config.Runner)
	resolveCancel()
	if resolveErr != nil {
		registered, version, moduleErr := inventoryWithSystemWinget(ctx, config.Runner)
		if moduleErr != nil {
			if approvedProgramFilesInstall(record, config) {
				record.WingetRegistered = true
				record.WingetVersion = record.ProgramFilesSSHD.Version
				return record, nil
			}
			return record, errors.Join(ErrInstallerUnavailable, resolveErr, moduleErr)
		}
		record.WingetRegistered, record.WingetVersion = registered, version
		return record, nil
	}
	listCtx, listCancel := context.WithTimeout(ctx, 15*time.Second)
	defer listCancel()
	// Inventory the local installed-package database. Supplying --source here
	// can trigger a source refresh lasting minutes and is unrelated to whether
	// the approved package is registered. Provision still pins --source winget.
	wingetOutput, listErr := config.Runner.Run(listCtx, wingetPath, "list", "--exact", "--id", PackageID, "--disable-interactivity")
	if listErr != nil {
		if noInstalledWingetPackage(string(wingetOutput)) {
			return record, nil
		}
		registered, version, moduleErr := inventoryWithSystemWinget(ctx, config.Runner)
		if moduleErr != nil {
			if approvedProgramFilesInstall(record, config) {
				record.WingetRegistered = true
				record.WingetVersion = record.ProgramFilesSSHD.Version
				return record, nil
			}
			return record, errors.Join(ErrInstallerUnavailable, errors.New(boundedOutput(wingetOutput)), listErr, moduleErr)
		}
		record.WingetRegistered, record.WingetVersion = registered, version
		return record, nil
	}
	record.WingetRegistered, record.WingetVersion = parseWingetPackageList(string(wingetOutput))
	return record, nil
}

// App Installer's package catalog is unavailable to LocalSystem on some
// Windows IoT builds. An already-installed OpenSSH tree may still be safely
// reused when its complete PE signature, publisher, architecture, path, and
// approved version are independently verified.
func approvedProgramFilesInstall(record InventoryRecord, config Config) bool {
	if !trustedBinary(record.ProgramFilesSSHD, config) {
		return false
	}
	if !versionMatches(record.ProgramFilesSSHD.Version, config.ApprovedVersion) {
		return false
	}
	return true
}

func inventoryPowerShell(config Config) string {
	installRoot := quotePowerShell(config.InstallRoot)
	return strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		securityModuleImport,
		"function A($p){$f=[IO.File]::Open($p,'Open','Read','Read');try{$r=[IO.BinaryReader]::new($f);if($r.ReadUInt16()-ne 0x5a4d){return ''};$f.Position=0x3c;$o=$r.ReadUInt32();$f.Position=$o;if($r.ReadUInt32()-ne 0x00004550){return ''};switch($r.ReadUInt16()){0x8664{'amd64'};0xaa64{'arm64'};default{''}}}finally{$f.Dispose()}}",
		"function B($p){$i=Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue;if($null -eq $i){return [pscustomobject]@{path=$p;exists=$false;regular=$false;reparse_point=$false;signature_valid=$false;publisher='';version='';architecture=''}};$s=Get-AuthenticodeSignature -LiteralPath $p;$v=$i.VersionInfo.FileVersion;[pscustomobject]@{path=$p;exists=$true;regular=(-not $i.PSIsContainer);reparse_point=(($i.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0);signature_valid=($s.Status -eq 'Valid');publisher=([string]$s.SignerCertificate.Subject);version=([string]$v);architecture=(A $p)}}",
		"function S($n){$x=Get-CimInstance Win32_Service -Filter (\"Name='\"+$n+\"'\") -ErrorAction SilentlyContinue;if($null -eq $x){return [pscustomobject]@{name=$n;exists=$false;state='';process_id=0;path_name=''}};[pscustomobject]@{name=$n;exists=$true;state=([string]$x.State);process_id=[uint32]$x.ProcessId;path_name=([string]$x.PathName)}}",
		"$cap=Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction SilentlyContinue|Where-Object {$_.State -eq 'Installed'}|Select-Object -First 1",
		"$root=" + installRoot,
		"[pscustomobject]@{winget_registered=$false;winget_version='';capability_present=($null -ne $cap);system_sshd=(B (Join-Path $env:WINDIR 'System32\\OpenSSH\\sshd.exe'));program_files_sshd=(B (Join-Path $root 'sshd.exe'));system_service=(S 'sshd');paperboat_service=(S 'PaperboatSshd')}|ConvertTo-Json -Compress -Depth 4",
	}, ";")
}

func quotePowerShell(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func parseWingetPackageList(output string) (bool, string) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for index, field := range fields {
			if !strings.EqualFold(field, PackageID) {
				continue
			}
			if index+1 < len(fields) {
				return true, fields[index+1]
			}
			return true, ""
		}
	}
	return false, ""
}

func noInstalledWingetPackage(output string) bool {
	return strings.Contains(strings.ToLower(output), "no installed package found matching input criteria")
}
