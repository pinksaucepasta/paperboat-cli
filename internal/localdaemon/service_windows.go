//go:build windows

package localdaemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

var runWindowsTaskCommand = defaultWindowsTaskCommand
var startWindowsDetachedDaemon = defaultStartWindowsDetachedDaemon

func installWindowsCurrentUserService(ctx context.Context, executable, configPath, serverURL string) error {
	if ctx == nil || !validWindowsExecutable(executable) || configPath != "" && !validWindowsConfigPath(configPath) || !validTaskText(serverURL) {
		return ErrInvalidInventoryConfig
	}
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	taskName := windowsDaemonTaskName(ownerSID)
	arguments := []string{"__local-daemon"}
	commandLine := quoteWindowsTaskArg(filepath.Clean(executable)) + " __local-daemon"
	if configPath != "" {
		arguments = append(arguments, "--config", filepath.Clean(configPath))
		commandLine += " --config " + quoteWindowsTaskArg(filepath.Clean(configPath))
	}
	if serverURL != "" {
		arguments = append(arguments, "--server", strings.TrimSpace(serverURL))
		commandLine += " --server " + quoteWindowsTaskArg(strings.TrimSpace(serverURL))
	}
	if err := runWindowsTaskCommand(ctx, "/Create", "/TN", taskName, "/TR", commandLine, "/SC", "ONLOGON", "/RL", "LIMITED", "/F"); err != nil {
		return fmt.Errorf("install Paperboat local daemon task: %w", err)
	}
	// Start immediately in the caller's authenticated user context. An ONLOGON
	// task cannot run in a non-interactive OpenSSH session, while an S4U task
	// cannot use the network credentials required by the client daemon. The
	// detached process covers the current session and the task restores it on
	// future interactive logons. The daemon's SID-bound process lock makes a
	// concurrent task launch harmless.
	if err := startWindowsDetachedDaemon(filepath.Clean(executable), arguments); err != nil {
		return fmt.Errorf("start Paperboat local daemon: %w", err)
	}
	return nil
}

func defaultStartWindowsDetachedDaemon(executable string, arguments []string) error {
	command := exec.Command(executable, arguments...)
	command.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func removeWindowsCurrentUserService(ctx context.Context, executable string) error {
	if ctx == nil || !validWindowsExecutable(executable) {
		return ErrInvalidInventoryConfig
	}
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	err = runWindowsTaskCommand(ctx, "/Delete", "/TN", windowsDaemonTaskName(ownerSID), "/F")
	if isMissingWindowsTaskError(err) {
		return nil
	}
	return err
}

func validWindowsExecutable(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func validWindowsConfigPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	return !strings.ContainsAny(path, "\x00\r\n")
}

func validTaskText(value string) bool {
	return len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

func windowsDaemonTaskName(ownerSID string) string {
	sum := sha256.Sum256([]byte(ownerSID))
	return "\\Paperboat\\LocalDaemon-" + hex.EncodeToString(sum[:8])
}

func quoteWindowsTaskArg(value string) string {
	if value == "" {
		return "\"\""
	}
	if !strings.ContainsAny(value, " \t\"") {
		return value
	}
	return "\"" + strings.ReplaceAll(value, "\"", "\\\"") + "\""
}

func defaultWindowsTaskCommand(ctx context.Context, arguments ...string) error {
	if ctx == nil {
		return ErrInvalidInventoryConfig
	}
	executable := filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
	if !validWindowsSystemExecutable(executable) {
		var err error
		executable, err = exec.LookPath("schtasks.exe")
		if err != nil {
			return err
		}
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return &windowsTaskCommandError{err: err, output: redactTaskOutput(output)}
	}
	return nil
}

func validWindowsSystemExecutable(path string) bool {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

type windowsTaskCommandError struct {
	err    error
	output string
}

func (e *windowsTaskCommandError) Error() string {
	if e == nil {
		return ""
	}
	if e.output == "" {
		return e.err.Error()
	}
	return e.err.Error() + ": " + e.output
}

func (e *windowsTaskCommandError) Unwrap() error { return e.err }

func redactTaskOutput(value []byte) string {
	const maximum = 4096
	if len(value) > maximum {
		value = value[:maximum]
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r >= 0x20 {
			return r
		}
		return ' '
	}, string(value)))
}

func isMissingWindowsTaskError(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "does not exist") || strings.Contains(value, "cannot find") || strings.Contains(value, "not found")
}
