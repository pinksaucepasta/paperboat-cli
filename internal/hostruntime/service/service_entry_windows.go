//go:build windows

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var ErrWindowsServiceEntry = errors.New("invalid Windows Paperboat service entry")
var ErrEnrolledOwnerMissing = errors.New("enrolled Windows owner account no longer exists")

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
	// LaunchFailure receives a startup error before SCM transitions to stopped.
	// Production callers use this for bounded service diagnostics; native
	// qualification uses it to preserve exact S4U failure evidence.
	LaunchFailure func(error)
	// DeleteOnExit is used only by one-shot dynamic preview services. The
	// LocalSystem parent removes its own SCM registration after the enrolled
	// owner workload exits, so expiry and worker cleanup never require UAC.
	DeleteOnExit bool
	// StartPrivilegedSidecar starts fixed LocalSystem-only infrastructure owned
	// by the SCM parent. The returned function must stop it synchronously.
	StartPrivilegedSidecar func(context.Context) (PrivilegedSidecar, error)
}

type PrivilegedSidecar struct{ Done <-chan error }

// RunWindowsService enters the SCM callback loop. It is intended to be
// called by the fixed Paperboat executable selected by the service manager.
func RunWindowsService(config ServiceEntryConfig) error {
	if err := validateServiceEntry(config); err != nil {
		return err
	}
	return svc.Run(config.Name, &serviceEntry{config: config})
}

// RunWindowsSystemService runs a fixed LocalSystem workload behind the SCM
// dispatcher. It is used for the updater, whose work is machine-owned and must
// not be launched through the enrolled user's token.
func RunWindowsSystemService(name string, run func(context.Context) error) error {
	if name == "" || len(name) > 256 || run == nil {
		return ErrWindowsServiceEntry
	}
	return svc.Run(name, &systemServiceEntry{run: run})
}

type systemServiceEntry struct{ run func(context.Context) error }

func (s *systemServiceEntry) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	accepts := svc.AcceptStop | svc.AcceptShutdown
	statuses <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case err := <-done:
			if err != nil {
				statuses <- stoppedServiceStatus(1, true)
				return true, 1
			}
			statuses <- stoppedServiceStatus(0, false)
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending, Accepts: accepts}
				cancel()
				err := <-done
				if err != nil && !errors.Is(err, context.Canceled) {
					statuses <- stoppedServiceStatus(1, true)
					return true, 1
				}
				statuses <- stoppedServiceStatus(0, false)
				return false, 0
			}
		}
	}
}

type serviceEntry struct{ config ServiceEntryConfig }

func (s *serviceEntry) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending, WaitHint: 90_000, CheckPoint: 1}
	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	var sidecar PrivilegedSidecar
	sidecarExited := false
	var sidecarExitErr error
	if s.config.StartPrivilegedSidecar != nil {
		var err error
		sidecar, err = s.config.StartPrivilegedSidecar(parentCtx)
		if err != nil {
			if s.config.LaunchFailure != nil {
				s.config.LaunchFailure(err)
			}
			statuses <- stoppedServiceStatus(1, true)
			return true, 1
		}
		if sidecar.Done == nil {
			statuses <- stoppedServiceStatus(1, true)
			return true, 1
		}
	}
	process, err := launchEnrolledProcess(s.config)
	if err != nil {
		if process != nil {
			err = errors.Join(err, process.Close())
		}
		if s.config.LaunchFailure != nil {
			s.config.LaunchFailure(err)
		}
		cancelParent()
		if sidecar.Done != nil {
			select {
			case sidecarErr := <-sidecar.Done:
				if sidecarErr != nil && !onlyContextCanceled(sidecarErr) && s.config.LaunchFailure != nil {
					s.config.LaunchFailure(sidecarErr)
				}
			case <-time.After(15 * time.Second):
				if s.config.LaunchFailure != nil {
					s.config.LaunchFailure(windows.ERROR_TIMEOUT)
				}
			}
		}
		statuses <- stoppedServiceStatus(1, true)
		return true, 1
	}
	processClosed := false
	closeProcess := func() error {
		if processClosed {
			return nil
		}
		if err := process.Close(); err != nil {
			return err
		}
		processClosed = true
		return nil
	}
	finish := func(code uint32, failed bool) (bool, uint32) {
		cleanupDone := make(chan error, 1)
		go func() {
			cleanupErr := closeProcess()
			if cleanupErr != nil {
				cleanupErr = errors.Join(cleanupErr, closeProcess())
			}
			cancelParent()
			cleanupErr = errors.Join(cleanupErr, sidecarExitErr)
			if !sidecarExited && sidecar.Done != nil {
				select {
				case sidecarErr := <-sidecar.Done:
					sidecarExited = true
					if sidecarErr != nil && !onlyContextCanceled(sidecarErr) {
						cleanupErr = errors.Join(cleanupErr, sidecarErr)
					}
				case <-time.After(15 * time.Second):
					cleanupErr = errors.Join(cleanupErr, windows.ERROR_TIMEOUT)
				}
			}
			cleanupDone <- cleanupErr
		}()
		checkpoint := uint32(1)
		statuses <- svc.Status{State: svc.StopPending, WaitHint: 90_000, CheckPoint: checkpoint}
		progress := time.NewTicker(5 * time.Second)
		defer progress.Stop()
		var closeErr error
	waitForCleanup:
		for {
			select {
			case closeErr = <-cleanupDone:
				break waitForCleanup
			case <-progress.C:
				checkpoint++
				statuses <- svc.Status{State: svc.StopPending, WaitHint: 90_000, CheckPoint: checkpoint}
			}
		}
		if closeErr != nil {
			if s.config.LaunchFailure != nil {
				s.config.LaunchFailure(closeErr)
			}
			code = 1
			failed = true
		}
		statuses <- stoppedServiceStatus(code, failed)
		return failed, code
	}
	var waitHandle windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), process.process, windows.CurrentProcess(), &waitHandle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return finish(1, true)
	}
	done := make(chan struct {
		code uint32
		err  error
	}, 1)
	go func() {
		waitResult, waitErr := windows.WaitForSingleObject(waitHandle, windows.INFINITE)
		var code uint32
		var exitErr error
		if waitErr != nil {
			exitErr = waitErr
		} else if waitResult != windows.WAIT_OBJECT_0 {
			exitErr = windows.ERROR_INVALID_HANDLE
		} else {
			exitErr = windows.GetExitCodeProcess(waitHandle, &code)
		}
		exitErr = errors.Join(exitErr, windows.Close(waitHandle))
		done <- struct {
			code uint32
			err  error
		}{code: code, err: exitErr}
	}()
	accepts := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange
	statuses <- svc.Status{State: svc.Running, Accepts: accepts}
	workloadInterrupted := false
	ownerChecks := time.NewTicker(30 * time.Second)
	defer ownerChecks.Stop()
	for {
		select {
		case sidecarErr := <-sidecar.Done:
			sidecarExited = true
			if sidecarErr != nil && !onlyContextCanceled(sidecarErr) {
				sidecarExitErr = sidecarErr
			}
			return finish(1, true)
		case exit := <-done:
			code := exit.code
			if exit.err != nil && s.config.LaunchFailure != nil {
				s.config.LaunchFailure(exit.err)
			}
			var deleteErr error
			if shouldDeleteOneShotService(s.config.DeleteOnExit, code, workloadInterrupted) {
				deleteErr = deleteOwnWindowsService(s.config.Name)
				if deleteErr != nil && s.config.LaunchFailure != nil {
					s.config.LaunchFailure(deleteErr)
				}
			}
			failed := exit.err != nil || code != 0 || workloadInterrupted || deleteErr != nil
			if failed && code == 0 {
				code = 1
			}
			return finish(code, failed)
		case <-ownerChecks.C:
			exists, checkErr := enrolledOwnerExists(s.config.EnrolledSID)
			if checkErr != nil || exists {
				continue
			}
			if s.config.LaunchFailure != nil {
				s.config.LaunchFailure(ErrEnrolledOwnerMissing)
			}
			return finish(1, true)
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				return finish(0, false)
			case svc.SessionChange:
				// Lock, unlock, disconnect, and fast-user switching retain the
				// enrolled workload. Only the enrolled user's logoff/termination
				// closes its job; SCM recovery waits for a new owner session.
				if shouldTerminateForSessionChange(request, process.sessionID) {
					workloadInterrupted = true
					if err := process.closeJob(); err != nil {
						if s.config.LaunchFailure != nil {
							s.config.LaunchFailure(err)
						}
						return finish(1, true)
					}
				}
			}
		}
	}
}

func enrolledOwnerExists(value string) (bool, error) {
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || !sid.IsValid() {
		return false, ErrWindowsServiceEntry
	}
	_, _, _, err = sid.LookupAccount("")
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return false, nil
	}
	return err == nil, err
}

func deleteOwnWindowsService(name string) (resultErr error) {
	definitionPath := filepath.Join(windowsServiceDefinitionRoot, name+".json")
	definition, err := readWindowsServiceDefinitionForRemoval(definitionPath)
	if err != nil {
		return err
	}
	stateRoot, err := validateWindowsOneShotPreviewDefinition(name, definition)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	current, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, current.Close()) }()
	serviceConfig, err := current.Config()
	if err != nil || !windowsServiceConfigurationOwnsDefinition(serviceConfig, definition) {
		return errors.Join(err, ErrWindowsServiceEntry)
	}
	if err := current.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	currentDefinition, err := readOwnedWindowsPreviewDefinitionForRemoval(definitionPath, name, stateRoot)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(currentDefinition, definition) {
		return ErrWindowsServiceEntry
	}
	if err := os.Remove(definitionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncServiceDirectory(windowsServiceDefinitionRoot)
}

func validateWindowsOneShotPreviewDefinition(name string, definition windowsServiceDefinition) (string, error) {
	if !isWindowsPreviewServiceName(name) {
		return "", ErrWindowsServiceEntry
	}
	stateRoot, ok := windowsPreviewStateRoot(definition.Arguments)
	if !ok {
		return "", ErrWindowsServiceEntry
	}
	definitionPath := filepath.Join(windowsServiceDefinitionRoot, name+".json")
	if err := validateWindowsPreviewDefinition(definitionPath, name, stateRoot, definition); err != nil {
		return "", err
	}
	return stateRoot, nil
}

func stoppedServiceStatus(code uint32, failed bool) svc.Status {
	if !failed {
		return svc.Status{State: svc.Stopped, Win32ExitCode: code}
	}
	return svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), ServiceSpecificExitCode: code}
}

func sessionChangeFor(request svc.ChangeRequest, sessionID uint32) bool {
	if request.EventData == 0 {
		return false
	}
	notification := (*windows.WTSSESSION_NOTIFICATION)(unsafe.Pointer(request.EventData))
	return notification.Size >= uint32(unsafe.Sizeof(*notification)) && notification.SessionID == sessionID
}

func shouldTerminateForSessionChange(request svc.ChangeRequest, sessionID uint32) bool {
	return sessionChangeFor(request, sessionID) && (request.EventType == windows.WTS_SESSION_LOGOFF || request.EventType == windows.WTS_SESSION_TERMINATE)
}

func onlyContextCanceled(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyContextCanceled(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyContextCanceled(wrapped.Unwrap())
	}
	return err == context.Canceled
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

type enrolledProcess struct {
	process                 windows.Handle
	job                     windows.Handle
	jobTerminationRequested bool
	sessionID               uint32
	profile                 *loadedOwnerProfile
}

func (p *enrolledProcess) Close() error {
	if err := p.closeJob(); err != nil {
		return err
	}
	if p.process != 0 {
		waitResult, waitErr := windows.WaitForSingleObject(p.process, 15_000)
		if waitErr != nil {
			return waitErr
		}
		if waitResult != windows.WAIT_OBJECT_0 {
			return windows.ERROR_TIMEOUT
		}
		if err := windows.Close(p.process); err != nil {
			return err
		}
		p.process = 0
	}
	if p.job != 0 {
		if err := waitWindowsJobEmpty(p.job, 15*time.Second); err != nil {
			return err
		}
		if err := windows.Close(p.job); err != nil {
			return err
		}
		p.job = 0
	}
	if p.profile != nil {
		if err := p.profile.Close(); err != nil {
			return err
		}
		p.profile = nil
	}
	return nil
}

func (p *enrolledProcess) closeJob() error {
	if p.job == 0 || p.jobTerminationRequested {
		return nil
	}
	if err := windows.TerminateJobObject(p.job, 1); err != nil {
		return err
	}
	p.jobTerminationRequested = true
	return nil
}

type windowsJobBasicAccountingInformation struct {
	PerProcessUserTime       int64
	PerJobUserTime           int64
	ThisPeriodUserTime       int64
	ThisPeriodKernelTime     int64
	TotalPageFaultCount      uint32
	TotalProcesses           uint32
	ActiveProcesses          uint32
	TotalTerminatedProcesses uint32
}

var _ [48 - unsafe.Sizeof(windowsJobBasicAccountingInformation{})]byte
var _ [unsafe.Sizeof(windowsJobBasicAccountingInformation{}) - 48]byte
var _ [40 - unsafe.Offsetof(windowsJobBasicAccountingInformation{}.ActiveProcesses)]byte
var _ [unsafe.Offsetof(windowsJobBasicAccountingInformation{}.ActiveProcesses) - 40]byte

func waitWindowsJobEmpty(job windows.Handle, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var accounting windowsJobBasicAccountingInformation
		var returned uint32
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), &returned); err != nil {
			return err
		}
		if returned < uint32(unsafe.Sizeof(accounting)) {
			return windows.ERROR_INVALID_DATA
		}
		if accounting.ActiveProcesses == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return windows.ERROR_TIMEOUT
		}
		//paperboat:allow-source-policy sleep owner=windows-service reason=bounded-job-accounting-quiescence-poll
		time.Sleep(20 * time.Millisecond)
	}
}

func launchEnrolledProcess(config ServiceEntryConfig) (result *enrolledProcess, resultErr error) {
	dropPrivileges, err := enableOwnerLaunchPrivileges()
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, dropPrivileges()) }()
	queried, sessionID, profile, err := enrolledSessionToken(config.EnrolledSID)
	if err != nil {
		var cleanupErr error
		if profile != nil {
			cleanupErr = errors.Join(cleanupErr, profile.Close())
		}
		if queried != 0 {
			cleanupErr = errors.Join(cleanupErr, queried.Close())
		}
		return nil, errors.Join(err, cleanupErr)
	}
	defer func() { resultErr = errors.Join(resultErr, queried.Close()) }()
	if profile != nil {
		defer func() {
			if profile != nil {
				resultErr = errors.Join(resultErr, profile.Close())
			}
		}()
	}
	var primary windows.Token
	access := uint32(windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_DUPLICATE | windows.TOKEN_IMPERSONATE | windows.TOKEN_QUERY | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID | windows.TOKEN_ADJUST_PRIVILEGES)
	if err := windows.DuplicateTokenEx(queried, access, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, primary.Close()) }()
	if err := validateOwnerToken(primary, config.EnrolledSID); err != nil {
		return nil, err
	}
	if err := stripOwnerTokenPrivileges(primary); err != nil {
		return nil, err
	}

	commandLine := windows.ComposeCommandLine(append([]string{config.Executable}, config.Arguments...))
	command, err := windows.UTF16FromString(commandLine)
	if err != nil {
		return nil, err
	}
	workingDirectory, err := primary.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
	if err != nil || !filepath.IsAbs(workingDirectory) || filepath.Clean(workingDirectory) != workingDirectory {
		return nil, ErrWindowsServiceEntry
	}
	workingDirectoryUTF16, err := windows.UTF16PtrFromString(workingDirectory)
	if err != nil {
		return nil, err
	}
	environment, err := ownerEnvironment(primary, config.Environment)
	if err != nil {
		return nil, err
	}
	startup := enrolledProcessStartupInfo()
	var processInfo windows.ProcessInformation
	// The process must not execute before its kill-on-close job owns it. In
	// particular, a fast process could otherwise create grandchildren between
	// CreateProcessAsUser and AssignProcessToJobObject.
	flags := enrolledProcessCreationFlags()
	if err := windows.CreateProcessAsUser(primary, nil, &command[0], nil, nil, false, flags, &environment[0], workingDirectoryUTF16, &startup, &processInfo); err != nil {
		return nil, err
	}
	job, err := killOnCloseJob()
	if err != nil {
		return nil, errors.Join(err, cleanFailedEnrolledLaunch(processInfo, 0))
	}
	if err := windows.AssignProcessToJobObject(job, processInfo.Process); err != nil {
		return nil, errors.Join(err, cleanFailedEnrolledLaunch(processInfo, job))
	}
	if _, err := windows.ResumeThread(processInfo.Thread); err != nil {
		return nil, errors.Join(err, cleanFailedEnrolledLaunch(processInfo, job))
	}
	if err := windows.Close(processInfo.Thread); err != nil {
		return nil, errors.Join(err, cleanFailedEnrolledLaunch(processInfo, job))
	}
	result = &enrolledProcess{process: processInfo.Process, job: job, sessionID: sessionID, profile: profile}
	profile = nil
	return result, nil
}

func enrolledProcessStartupInfo() windows.StartupInfo {
	return windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
	}
}

func enrolledProcessCreationFlags() uint32 {
	return windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED
}

func cleanFailedEnrolledLaunch(info windows.ProcessInformation, job windows.Handle) error {
	var result error
	if info.Thread != 0 {
		result = errors.Join(result, windows.Close(info.Thread))
	}
	if job != 0 {
		result = errors.Join(result, windows.TerminateJobObject(job, 1))
	}
	if info.Process != 0 {
		result = errors.Join(result, windows.TerminateProcess(info.Process, 1))
		waitResult, waitErr := windows.WaitForSingleObject(info.Process, 15_000)
		if waitErr != nil {
			result = errors.Join(result, waitErr)
		} else if waitResult != windows.WAIT_OBJECT_0 {
			result = errors.Join(result, windows.ERROR_TIMEOUT)
		} else {
			result = errors.Join(result, windows.Close(info.Process))
		}
	}
	if job != 0 {
		if err := waitWindowsJobEmpty(job, 15*time.Second); err != nil {
			result = errors.Join(result, err)
		} else {
			result = errors.Join(result, windows.Close(job))
		}
	}
	return result
}

func enrolledSessionToken(enrolledSID string) (windows.Token, uint32, *loadedOwnerProfile, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return s4uOwnerToken(enrolledSID)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	if count == 0 || sessions == nil {
		return s4uOwnerToken(enrolledSID)
	}
	var closeErr error
	candidates := append([]windows.WTS_SESSION_INFO(nil), unsafe.Slice(sessions, int(count))...)
	sort.Slice(candidates, func(i, j int) bool {
		left, right := sessionPriority(candidates[i].State), sessionPriority(candidates[j].State)
		if left != right {
			return left < right
		}
		return candidates[i].SessionID < candidates[j].SessionID
	})
	for _, candidate := range candidates {
		if sessionPriority(candidate.State) > 2 {
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(candidate.SessionID, &token); err != nil {
			continue
		}
		user, err := token.GetTokenUser()
		if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.String() == enrolledSID {
			return token, candidate.SessionID, nil, nil
		}
		closeErr = errors.Join(closeErr, token.Close())
	}
	resultToken, resultSession, resultProfile, resultErr := s4uOwnerToken(enrolledSID)
	return resultToken, resultSession, resultProfile, errors.Join(closeErr, resultErr)
}

func sessionPriority(state uint32) int {
	switch state {
	case windows.WTSActive:
		return 0
	case windows.WTSConnected:
		return 1
	case windows.WTSDisconnected:
		return 2
	default:
		return 3
	}
}

func ownerEnvironment(token windows.Token, overrides map[string]string) ([]uint16, error) {
	values := make(map[string]string)
	environment, err := token.Environ(false)
	if err != nil {
		return nil, err
	}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[strings.ToUpper(key)] = value
		}
	}
	for key, value := range overrides {
		values[strings.ToUpper(key)] = value
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
	block := make([]uint16, 0, len(entries)*16+1)
	for _, entry := range entries {
		if strings.ContainsRune(entry, '\x00') {
			return nil, windows.ERROR_INVALID_PARAMETER
		}
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, err
		}
		block = append(block, encoded...)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}

func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return 0, errors.Join(err, windows.Close(job))
	}
	return job, nil
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
