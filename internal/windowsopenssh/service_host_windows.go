//go:build windows

package windowsopenssh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// RunServiceHost runs the PaperboatSshd SCM entry point. sshd itself cannot be
// registered under an arbitrary service name, so the signed Paperboat binary
// owns the service and supervises the pinned sshd child.
func RunServiceHost(sshdPath, configPath string) error {
	if !filepath.IsAbs(sshdPath) || !filepath.IsAbs(configPath) {
		return ErrInvalidConfig
	}
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return errors.Join(ErrServiceOwnership, err)
	}
	return svc.Run(ServiceName, &sshdServiceHandler{sshdPath: sshdPath, configPath: configPath})
}

type sshdServiceHandler struct{ sshdPath, configPath string }

func (h *sshdServiceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, h.sshdPath, "-D", "-e", "-f", h.configPath)
	command.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	defer windows.Close(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	logPath := filepath.Join(filepath.Dir(h.configPath), "logs", "service.log")
	if logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		defer logFile.Close()
		command.Stdout = logFile
		command.Stderr = logFile
	}
	if err := command.Start(); err != nil {
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(command.Process.Pid))
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	assignErr := windows.AssignProcessToJobObject(job, processHandle)
	windows.Close(processHandle)
	if assignErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					_ = command.Process.Kill()
					<-done
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-done:
			status <- svc.Status{State: svc.Stopped}
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}
