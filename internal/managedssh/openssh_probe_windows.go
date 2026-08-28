//go:build windows

package managedssh

import (
	"context"
	"errors"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runOpenSSHProbeCommand runs a probe in a kill-on-close job. OpenSSH options
// can launch helper processes, and killing only ssh.exe leaves those helpers
// holding the output pipes open. That makes exec.Cmd.Wait appear to ignore a
// context deadline. The job bounds the complete native process tree.
func runOpenSSHProbeCommand(ctx context.Context, command *exec.Cmd) error {
	command.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer windows.Close(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(command.Process.Pid))
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return err
	}
	assignErr := windows.AssignProcessToJobObject(job, processHandle)
	_ = windows.Close(processHandle)
	if assignErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return errors.Join(errors.New("OpenSSH probe process could not be bounded"), assignErr)
	}
	stop := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = windows.TerminateJobObject(job, 1)
		case <-stop:
		}
	}()
	err = command.Wait()
	close(stop)
	<-watchDone
	return err
}

func openSSHProbeKnownHostsCommand() string {
	return "none"
}
