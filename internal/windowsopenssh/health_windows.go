//go:build windows

package windowsopenssh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func collectLoopbackHealth(ctx context.Context, config Config, result Result) (ServiceHealth, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"$s=Get-CimInstance Win32_Service -Filter \"Name='PaperboatSshd'\" -ErrorAction SilentlyContinue",
		"if($null -eq $s){[pscustomobject]@{service=[pscustomobject]@{name='PaperboatSshd';exists=$false;state='';process_id=0;path_name=''};listeners=@()}|ConvertTo-Json -Compress;exit 0}",
		"$ls=@(Get-NetTCPConnection -State Listen -LocalPort " + fmt.Sprint(result.Port) + " -ErrorAction SilentlyContinue|ForEach-Object {$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$_.OwningProcess) -ErrorAction SilentlyContinue;[pscustomobject]@{address=([string]$_.LocalAddress);port=[uint16]$_.LocalPort;process_id=[uint32]$_.OwningProcess;parent_process_id=[uint32]$p.ParentProcessId;executable_path=([string]$p.ExecutablePath)}})",
		"[pscustomobject]@{service=[pscustomobject]@{name='PaperboatSshd';exists=$true;state=([string]$s.State);process_id=[uint32]$s.ProcessId;path_name=([string]$s.PathName)};listeners=$ls}|ConvertTo-Json -Compress -Depth 4",
	}, ";")
	output, err := config.Runner.Run(probeCtx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return ServiceHealth{}, fmt.Errorf("%w: %s", ErrServiceUnhealthy, boundedOutput(output))
	}
	var health ServiceHealth
	if err := json.Unmarshal(output, &health); err != nil {
		return ServiceHealth{}, fmt.Errorf("%w: decode loopback health: %v", ErrServiceUnhealthy, err)
	}
	return health, nil
}
