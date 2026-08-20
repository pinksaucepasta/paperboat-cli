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

func snapshotFirewall(ctx context.Context, config Config) (FirewallSnapshot, error) {
	timed, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"function Convert-PaperboatFirewallRule($r){$p=$r|Get-NetFirewallPortFilter -ErrorAction SilentlyContinue|Select-Object -First 1;$a=$r|Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue|Select-Object -First 1;[pscustomobject]@{name=([string]$r.Name);display_name=([string]$r.DisplayName);direction=([string]$r.Direction);action=([string]$r.Action);enabled=([bool]($r.Enabled -eq 'True'));profiles=([string]$r.Profile);program=([string]$a.Program);service=([string]$a.Service);protocol=([string]$p.Protocol);local_port=([string]$p.LocalPort)}}",
		"$named=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -ErrorAction Stop|Where-Object {(($_.Name+' '+$_.DisplayName+' '+$_.Service)-match '(?i)openssh|sshd')})",
		"$byProgram=@(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {$_.Program -match '(?i)sshd\\.exe$'}|Get-NetFirewallRule -ErrorAction SilentlyContinue|Where-Object {$_.Direction -eq 'Inbound'})",
		"$seen=@{};$rules=@(@($named)+@($byProgram)|ForEach-Object {if(-not $seen.ContainsKey($_.Name)){$seen[$_.Name]=$true;Convert-PaperboatFirewallRule $_}})",
		"$system=($null -ne (Get-Service -Name sshd -ErrorAction SilentlyContinue))",
		"$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop|ForEach-Object {[pscustomobject]@{name=([string]$_.Name);enabled=([bool]($_.Enabled -eq 'True'));default_inbound_action=([string]$_.DefaultInboundAction)}})",
		"[pscustomobject]@{captured_at=[DateTime]::UtcNow.ToString('o');system_sshd=$system;profiles=$profiles;openssh_inbound=$rules}|ConvertTo-Json -Compress -Depth 4",
	}, ";")
	output, err := config.Runner.Run(timed, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return FirewallSnapshot{}, fmt.Errorf("%w: %s", ErrFirewallSnapshot, boundedOutput(output))
	}
	var snapshot FirewallSnapshot
	if err := json.Unmarshal(output, &snapshot); err != nil {
		return FirewallSnapshot{}, errors.Join(ErrFirewallSnapshot, err)
	}
	if snapshot.CapturedAt.IsZero() {
		return FirewallSnapshot{}, ErrFirewallSnapshot
	}
	return snapshot, nil
}

func disableOwnedFirewallRule(ctx context.Context, config Config, name string) error {
	return mutateOwnedFirewallRule(ctx, config, name, "Set-NetFirewallRule -Name ")
}
func removeOwnedFirewallRule(ctx context.Context, config Config, name string) error {
	return mutateOwnedFirewallRule(ctx, config, name, "Remove-NetFirewallRule -Name ")
}
func mutateOwnedFirewallRule(ctx context.Context, config Config, name, operation string) error {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n\x00") {
		return ErrFirewallOwnership
	}
	timed, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	script := "$ErrorActionPreference='Stop';" + operation + quotePowerShell(name) + " -ErrorAction Stop" + func() string {
		if strings.HasPrefix(operation, "Set-") {
			return " -Enabled False"
		}
		return ""
	}()
	output, err := config.Runner.Run(timed, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return errors.New(boundedOutput(output))
	}
	return nil
}
