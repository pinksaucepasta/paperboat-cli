//go:build windows && paperboat_native_e2e

package e2e

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/conpty"
)

func TestNativeConPTYPowerShell51(t *testing.T) {
	powershell := filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	assertConPTYCommand(t, powershell, []string{
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
		"[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); Write-Output 'paperboat-conpty-powershell51'; exit 0",
	}, "paperboat-conpty-powershell51")
}

func TestNativeConPTYPowerShell7(t *testing.T) {
	powershell, err := findPowerShell7()
	if err != nil {
		t.Fatalf("PowerShell 7 (pwsh.exe) is required: %v", err)
	}
	assertConPTYCommand(t, powershell, []string{
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
		"[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); Write-Output 'paperboat-conpty-powershell7'; exit 0",
	}, "paperboat-conpty-powershell7")
}

func findPowerShell7() (string, error) {
	candidates := []string{
		os.Getenv("PAPERBOAT_PWSH_PATH"),
		filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7-preview", "pwsh.exe"),
	}
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		candidates = append(candidates, filepath.Join(localAppData, "Microsoft", "PowerShell", "7", "pwsh.exe"))
	}
	// Qualification runs as LocalSystem, while developers commonly install
	// PowerShell 7 per-user. Locate those standard per-user installations too.
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = `C:`
	}
	if matches, _ := filepath.Glob(filepath.Join(systemDrive, "Users", "*", "AppData", "Local", "Microsoft", "PowerShell", "7", "pwsh.exe")); len(matches) > 0 {
		candidates = append(candidates, matches...)
	}
	// Codex ships a native PowerShell runtime on Windows. It is a supported
	// PowerShell 7 executable even when the interactive user's package is not
	// registered in LocalSystem's PATH.
	if matches, _ := filepath.Glob(filepath.Join(systemDrive, "Users", "*", ".cache", "codex-runtimes", "*", "dependencies", "native", "powershell", "pwsh.exe")); len(matches) > 0 {
		candidates = append(candidates, matches...)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return exec.LookPath("pwsh.exe")
}

func TestNativeConPTYCmd(t *testing.T) {
	commandShell := os.Getenv("ComSpec")
	if commandShell == "" {
		commandShell = filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe")
	}
	// Keep the /C command tokenized. cmd.exe applies shell-specific quote
	// rewriting to a single quoted command body, while CreateProcess only
	// provides the raw Windows command line.
	assertConPTYCommand(t, commandShell, []string{"/d", "/c", "echo.paperboat-conpty-cmd"}, "paperboat-conpty-cmd")
}

func assertConPTYCommand(t *testing.T, executable string, args []string, want string) {
	t.Helper()
	output, exitCode, err := runConPTY(executable, args)
	if err != nil {
		t.Fatalf("ConPTY %s: %v", executable, err)
	}
	if exitCode != 0 {
		t.Fatalf("ConPTY %s exit code=%d output=%q", executable, exitCode, output)
	}
	ansi := regexp.MustCompile("\\x1b\\[[0-?]*[ -/]*[@-~]")
	clean := ansi.ReplaceAllString(output, "")
	if !strings.Contains(clean, want) {
		t.Fatalf("ConPTY %s output=%q does not contain %q", executable, clean, want)
	}
}

func runConPTY(executable string, args []string) (string, uint32, error) {
	if executable == "" || !filepath.IsAbs(executable) {
		return "", 0, fmt.Errorf("executable is not absolute: %q", executable)
	}
	pty, err := conpty.NewPseudoConsole(windows.Coord{X: 80, Y: 25})
	if err != nil {
		return "", 0, fmt.Errorf("create pseudoconsole: %w", err)
	}
	defer pty.Close()
	if err := pty.Resize(windows.Coord{X: 120, Y: 30}); err != nil {
		return "", 0, fmt.Errorf("resize pseudoconsole: %w", err)
	}
	var startup winutil.StartupInfoBuilder
	defer startup.Close()
	if err := pty.ConfigureStartupInfo(&startup); err != nil {
		return "", 0, fmt.Errorf("configure pseudoconsole startup: %w", err)
	}
	startupInfo, inheritHandles, creationFlags, err := startup.Resolve()
	if err != nil {
		return "", 0, fmt.Errorf("resolve pseudoconsole startup: %w", err)
	}
	executable16, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return "", 0, err
	}
	commandLine := syscall.EscapeArg(executable)
	for _, arg := range args {
		commandLine += " " + syscall.EscapeArg(arg)
	}
	commandLine16, err := windows.UTF16FromString(commandLine)
	if err != nil {
		return "", 0, err
	}
	var process windows.ProcessInformation
	if err := windows.CreateProcess(executable16, &commandLine16[0], nil, nil, inheritHandles, creationFlags, nil, nil, startupInfo, &process); err != nil {
		return "", 0, fmt.Errorf("create pseudoconsole child: %w", err)
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	outputDone := make(chan []byte, 1)
	go func() {
		body, _ := io.ReadAll(pty.OutputPipe())
		outputDone <- body
	}()
	wait, waitErr := windows.WaitForSingleObject(process.Process, uint32((30 * time.Second).Milliseconds()))
	if waitErr != nil {
		return "", 0, fmt.Errorf("wait for pseudoconsole child: %w", waitErr)
	}
	if wait == uint32(windows.WAIT_TIMEOUT) {
		_ = windows.TerminateProcess(process.Process, 1)
		return "", 0, errors.New("pseudoconsole child timed out")
	}
	if wait != windows.WAIT_OBJECT_0 {
		return "", 0, fmt.Errorf("wait for pseudoconsole child returned %d", wait)
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process.Process, &exitCode); err != nil {
		return "", 0, fmt.Errorf("query pseudoconsole exit code: %w", err)
	}
	// The child process can exit before conhost has flushed its final screen
	// update into the pseudoconsole output pipe. Closing the HPCON immediately
	// races that flush and intermittently loses short cmd.exe output.
	time.Sleep(250 * time.Millisecond)
	// Closing the pseudo console releases the output pipe after the child exits;
	// the reader is still drained before the result is returned.
	if err := pty.Close(); err != nil {
		return "", 0, err
	}
	return string(<-outputDone), exitCode, nil
}
