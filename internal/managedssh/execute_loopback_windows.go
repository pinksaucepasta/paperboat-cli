//go:build windows

package managedssh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	openSSHLoopbackAcceptTimeout = 10 * time.Second
	openSSHLoopbackExitTimeout   = 5 * time.Second
)

// LoopbackOpenSSHExecutor runs Windows OpenSSH against a one-shot owner-bound
// loopback TCP proxy. This avoids the native ProxyCommand pipe shutdown cycle,
// while retaining OpenSSH's inherited console and exact exit status.
type LoopbackOpenSSHExecutor struct{}

func (LoopbackOpenSSHExecutor) Execute(ctx context.Context, executable string, arguments func(port uint16) []string, environment []string, stream LoopbackSSHStream) error {
	path, err := resolveOpenSSHExecutable(executable)
	if err != nil || ctx == nil || arguments == nil || stream == nil || !validEnvironment(environment) {
		if stream != nil {
			_ = stream.Close()
		}
		return ErrOpenSSHExecution
	}
	return runOneShotSSHLoopback(ctx, stream, openSSHLoopbackAcceptTimeout, openSSHLoopbackExitTimeout, func(port uint16) (loopbackSSHProcess, error) {
		values := arguments(port)
		if !validProcessValues(values) {
			return nil, ErrOpenSSHExecution
		}
		command := exec.Command(path, values...)
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		command.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
		if environment != nil {
			command.Env = append([]string(nil), environment...)
		}
		return startOpenSSHLoopbackProcess(command)
	}, verifyWindowsSSHLoopbackOwner)
}

type openSSHLoopbackProcess struct {
	command *exec.Cmd
	job     windows.Handle
}

func startOpenSSHLoopbackProcess(command *exec.Cmd) (loopbackSSHProcess, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.Close(job)
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = windows.Close(job)
		return nil, err
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(command.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, processHandle)
		_ = windows.Close(processHandle)
	}
	if err != nil {
		_ = command.Process.Kill()
		waitErr := command.Wait()
		_ = windows.Close(job)
		return nil, errors.Join(errors.New("OpenSSH process could not be bounded"), err, waitErr)
	}
	return &openSSHLoopbackProcess{command: command, job: job}, nil
}

func (p *openSSHLoopbackProcess) Wait() error {
	err := p.command.Wait()
	_ = windows.Close(p.job)
	return err
}

func (p *openSSHLoopbackProcess) Kill() error {
	return windows.TerminateJobObject(p.job, 1)
}

func (p *openSSHLoopbackProcess) PID() uint32 { return uint32(p.command.Process.Pid) }
