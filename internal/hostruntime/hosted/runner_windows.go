//go:build windows

package hosted

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ExecRunner struct{ OwnerSID string }

func (runner ExecRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil || command.Path == "" || command.OutputLimit <= 0 {
		return nil, ErrInvalid
	}
	if err := runner.requireOwner(); err != nil {
		return nil, err
	}
	job, err := newCommandJob()
	if err != nil {
		return nil, err
	}
	defer job.Close()
	output := limitedBuffer{limit: command.OutputLimit, abort: job.Close}
	process, outputFile, err := startCommandSuspended(ctx, job, command)
	if err != nil {
		return nil, err
	}
	defer process.Close()
	defer outputFile.Close()

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		buffer := make([]byte, 32<<10)
		for {
			n, readErr := outputFile.Read(buffer)
			if n > 0 {
				_, _ = output.Write(buffer[:n])
			}
			if readErr != nil {
				return
			}
		}
	}()

	stopCancellation := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = job.Close()
		case <-stopCancellation:
		}
	}()
	_, waitErr := windows.WaitForSingleObject(process.handle, windows.INFINITE)
	close(stopCancellation)
	// Closing a live command job after its direct child exits also terminates
	// descendants which inherited the output pipe. This matches Unix process
	// group ownership and lets the pipe reader finish deterministically.
	_ = job.Close()
	<-outputDone
	if output.Exceeded() {
		return nil, ErrOutputLimit
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if waitErr != nil {
		return output.Bytes(), waitErr
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process.handle, &exitCode); err != nil {
		return output.Bytes(), err
	}
	if exitCode != 0 {
		return output.Bytes(), commandExitError{code: exitCode}
	}
	return output.Bytes(), nil
}

type startedCommand struct{ handle windows.Handle }

func (process startedCommand) Close() error {
	if process.handle == 0 {
		return nil
	}
	return windows.Close(process.handle)
}

type commandExitError struct{ code uint32 }

func (err commandExitError) Error() string {
	return "hosted command exited with status " + strconv.FormatUint(uint64(err.code), 10)
}

// startCommandSuspended creates the command before it can execute, assigns it
// to the kill-on-close Job Object, then resumes its primary thread. Keeping
// this ordering prevents a child from spawning descendants outside the job.
func startCommandSuspended(ctx context.Context, job *commandJob, command Command) (startedCommand, *os.File, error) {
	var readPipe, writePipe windows.Handle
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err := windows.CreatePipe(&readPipe, &writePipe, &security, 0); err != nil {
		return startedCommand{}, nil, err
	}
	closePipes := func() {
		if readPipe != 0 {
			_ = windows.Close(readPipe)
		}
		if writePipe != 0 {
			_ = windows.Close(writePipe)
		}
	}
	if err := windows.SetHandleInformation(readPipe, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		closePipes()
		return startedCommand{}, nil, err
	}
	nul, err := windows.CreateFile(windows.StringToUTF16Ptr("NUL"), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &security, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		closePipes()
		return startedCommand{}, nil, err
	}
	closeChildHandles := func() {
		if writePipe != 0 {
			_ = windows.Close(writePipe)
			writePipe = 0
		}
		if nul != 0 {
			_ = windows.Close(nul)
			nul = 0
		}
	}
	defer closeChildHandles()

	commandLine := windows.ComposeCommandLine(append([]string{command.Path}, command.Args...))
	commandLineUTF16, err := windows.UTF16FromString(commandLine)
	if err != nil {
		closePipes()
		return startedCommand{}, nil, err
	}
	application, err := windows.UTF16PtrFromString(command.Path)
	if err != nil {
		closePipes()
		return startedCommand{}, nil, err
	}
	var workingDirectory *uint16
	if command.Dir != "" {
		workingDirectory, err = windows.UTF16PtrFromString(command.Dir)
		if err != nil {
			closePipes()
			return startedCommand{}, nil, err
		}
	}
	environment, err := commandEnvironment(command.Env)
	if err != nil {
		closePipes()
		return startedCommand{}, nil, err
	}
	startup := windows.StartupInfo{
		Cb:        uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:     windows.STARTF_USESTDHANDLES,
		StdInput:  nul,
		StdOutput: writePipe,
		StdErr:    writePipe,
	}
	var info windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED)
	if err := windows.CreateProcess(application, &commandLineUTF16[0], nil, nil, true, flags, &environment[0], workingDirectory, &startup, &info); err != nil {
		closePipes()
		return startedCommand{}, nil, err
	}
	terminate := func() {
		_ = job.Close()
		_ = windows.TerminateProcess(info.Process, 1)
		_ = windows.Close(info.Thread)
		_ = windows.Close(info.Process)
	}
	if err := job.Assign(info.Process); err != nil {
		terminate()
		closePipes()
		return startedCommand{}, nil, err
	}
	if err := contextError(ctx); err != nil {
		terminate()
		closePipes()
		return startedCommand{}, nil, err
	}
	if _, err := windows.ResumeThread(info.Thread); err != nil {
		terminate()
		closePipes()
		return startedCommand{}, nil, err
	}
	if err := windows.Close(info.Thread); err != nil {
		_ = job.Close()
		_ = windows.Close(info.Process)
		closePipes()
		return startedCommand{}, nil, err
	}
	info.Thread = 0
	output := os.NewFile(uintptr(readPipe), "paperboat-hosted-output")
	readPipe = 0
	return startedCommand{handle: info.Process}, output, nil
}

func commandEnvironment(environment []string) ([]uint16, error) {
	if environment == nil {
		environment = os.Environ()
	}
	entries := append([]string(nil), environment...)
	sort.SliceStable(entries, func(i, j int) bool {
		return strings.ToUpper(entries[i]) < strings.ToUpper(entries[j])
	})
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
	// CreateProcess requires an environment block terminated by an additional
	// NUL after the NUL that terminates the final entry.
	if len(block) == 0 {
		block = append(block, 0)
	}
	block = append(block, 0)
	return block, nil
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

type commandJob struct {
	handle windows.Handle
	once   sync.Once
	mu     sync.Mutex
	err    error
}

func newCommandJob() (*commandJob, error) {
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.Close(handle)
		return nil, err
	}
	return &commandJob{handle: handle}, nil
}

func (job *commandJob) Close() error {
	job.once.Do(func() {
		job.mu.Lock()
		defer job.mu.Unlock()
		if job.handle != 0 {
			job.err = windows.Close(job.handle)
			job.handle = 0
		}
	})
	return job.err
}

func (job *commandJob) Assign(process windows.Handle) error {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return windows.ERROR_INVALID_HANDLE
	}
	return windows.AssignProcessToJobObject(job.handle, process)
}

func (runner ExecRunner) requireOwner() error {
	if runner.OwnerSID == "" || strings.TrimSpace(os.Getenv("PAPERBOAT_WINDOWS_OWNER_WORKLOAD")) != "1" {
		return ErrInvalid
	}
	want, err := windows.StringToSid(runner.OwnerSID)
	if err != nil || want == nil || !want.IsValid() {
		return ErrInvalid
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.Equals(want) {
		return errors.Join(ErrInvalid, errors.New("hosted subprocess requires enrolled Windows owner token"))
	}
	return nil
}

type limitedBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	abort    func() error
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	if len(value) > b.limit-b.buffer.Len() {
		remaining := b.limit - b.buffer.Len()
		if remaining > 0 {
			_, _ = b.buffer.Write(value[:remaining])
		}
		abort := b.abort
		alreadyExceeded := b.exceeded
		b.exceeded = true
		b.mu.Unlock()
		if !alreadyExceeded && abort != nil {
			_ = abort()
		}
		return len(value), nil
	}
	n, err := b.buffer.Write(value)
	b.mu.Unlock()
	return n, err
}

func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

func (b *limitedBuffer) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

var _ Runner = ExecRunner{}
