//go:build windows

package service

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var ErrWindowsServiceEntry = errors.New("invalid Windows Paperboat service entry")

// ServiceEntryConfig is the fixed, generated service command. A service entry
// never accepts a caller-provided command line. The updater runs directly as
// LocalSystem; hostd uses the enrolled SID to obtain an interactive user token
// before starting the workload owner.
type ServiceEntryConfig struct {
	Name        string
	Executable  string
	Arguments   []string
	EnrolledSID string
	Environment map[string]string
}

// RunWindowsService enters the SCM callback loop. It is intended to be
// called by the fixed Paperboat executable selected by the service manager.
func RunWindowsService(config ServiceEntryConfig) error {
	if err := validateServiceEntry(config); err != nil {
		return err
	}
	return svc.Run(config.Name, &serviceEntry{config: config})
}

type serviceEntry struct{ config ServiceEntryConfig }

func (s *serviceEntry) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	process, err := launchEnrolledProcess(s.config)
	if err != nil {
		statuses <- svc.Status{State: svc.Stopped, Win32ExitCode: 1}
		return false, 1
	}
	defer windows.Close(process)
	done := make(chan uint32, 1)
	go func() {
		_, _ = windows.WaitForSingleObject(process, windows.INFINITE)
		var code uint32
		_ = windows.GetExitCodeProcess(process, &code)
		done <- code
	}()
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case code := <-done:
			statuses <- svc.Status{State: svc.Stopped, Win32ExitCode: code}
			return false, code
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				_ = windows.TerminateProcess(process, 0)
				code := <-done
				statuses <- svc.Status{State: svc.Stopped, Win32ExitCode: code}
				return false, code
			}
		}
	}
}

func validateServiceEntry(config ServiceEntryConfig) error {
	if config.Name == "" || len(config.Name) > 256 || !filepath.IsAbs(config.Executable) || strings.EqualFold(filepath.Ext(config.Executable), ".exe") == false || len(config.Arguments) > 32 || !validServiceSID(config.EnrolledSID) {
		return ErrWindowsServiceEntry
	}
	info, err := os.Lstat(config.Executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrWindowsServiceEntry
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(config.Executable))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrWindowsServiceEntry
	}
	for _, argument := range config.Arguments {
		if argument == "" || len(argument) > 4096 || strings.ContainsAny(argument, "\x00\r\n") {
			return ErrWindowsServiceEntry
		}
	}
	for key, value := range config.Environment {
		if !serviceEntryEnvironmentKey(key) || strings.ContainsAny(value, "\x00\r\n") {
			return ErrWindowsServiceEntry
		}
	}
	return nil
}

func launchEnrolledProcess(config ServiceEntryConfig) (windows.Handle, error) {
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xffffffff {
		return 0, ErrWindowsServiceEntry
	}
	var queried windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &queried); err != nil {
		return 0, err
	}
	defer queried.Close()
	user, err := queried.GetTokenUser()
	if err != nil || user.User.Sid == nil || user.User.Sid.String() != config.EnrolledSID {
		return 0, ErrWindowsServiceEntry
	}
	var primary windows.Token
	access := uint32(windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID)
	if err := windows.DuplicateTokenEx(queried, access, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return 0, err
	}
	defer primary.Close()
	// The duplicated interactive token must not carry administrative
	// privileges into the hostd process. Disabling every privilege leaves the
	// user SID/groups needed for desktop access while removing SeDebug,
	// SeTcb, backup/restore, and other service-only capabilities.
	if err := windows.AdjustTokenPrivileges(primary, true, nil, 0, nil, nil); err != nil {
		return 0, err
	}

	commandLine := syscallEscape(config.Executable)
	for _, argument := range config.Arguments {
		commandLine += " " + syscallEscape(argument)
	}
	command, err := windows.UTF16FromString(commandLine)
	if err != nil {
		return 0, err
	}
	workingDirectory, err := windows.UTF16PtrFromString(filepath.Dir(config.Executable))
	if err != nil {
		return 0, err
	}
	environment, err := serviceEnvironment(config.Environment)
	if err != nil {
		return 0, err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var processInfo windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_PROCESS_GROUP)
	if err := windows.CreateProcessAsUser(primary, nil, &command[0], nil, nil, false, flags, environment, workingDirectory, &startup, &processInfo); err != nil {
		return 0, err
	}
	windows.Close(processInfo.Thread)
	return processInfo.Process, nil
}

func serviceEnvironment(overrides map[string]string) (*uint16, error) {
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[strings.ToUpper(key)] = value
		}
	}
	for key, value := range overrides {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([]string, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, key+"="+values[key])
	}
	return windows.UTF16PtrFromString(strings.Join(entries, "\x00") + "\x00")
}

func syscallEscape(value string) string {
	if value == "" {
		return `""`
	}
	if !strings.ContainsAny(value, " \t\"") {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func serviceEntryEnvironmentKey(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validServiceSID(value string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.String() == value
}
