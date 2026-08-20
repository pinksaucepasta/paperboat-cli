//go:build windows

package execprocess

import (
	"context"
	"errors"
	"io"
	"os"
	osExec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"golang.org/x/sys/windows"
)

type processConfig struct {
	Request         Request
	WorkspaceRoot   string
	BaseEnvironment []string
	ChunkBytes      int
	Output          func(string, []byte)
}

func newProcess(config processConfig) (process, error) {
	if config.Request.PTY {
		return &ptyProcess{config: config}, nil
	}
	return &pipeProcess{config: config, done: make(chan struct{})}, nil
}

type pipeProcess struct {
	config    processConfig
	cmd       *osExec.Cmd
	stdin     io.WriteCloser
	job       windows.Handle
	done      chan struct{}
	mu        sync.RWMutex
	result    Result
	waitErr   error
	closeOnce sync.Once
}

func (p *pipeProcess) Start(context.Context) error {
	environment := mergedEnvironment(p.config.BaseEnvironment, p.config.Request.Environment)
	path, err := lookPath(p.config.Request.Argv[0], environment)
	if err != nil {
		return ErrInvalid
	}
	cmd := osExec.Command(path, p.config.Request.Argv[1:]...)
	cmd.Args[0], cmd.Dir, cmd.Env = p.config.Request.Argv[0], p.config.Request.CWD, environment
	// Start suspended so the process cannot exit or create descendants before
	// Paperboat assigns it to the kill-on-close Job Object.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return err
	}
	job, err := newKillOnCloseJob()
	if err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		windows.Close(job)
		_ = cmd.Process.Kill()
		return err
	}
	if err := windows.AssignProcessToJobObject(job, processHandle); err != nil {
		windows.Close(processHandle)
		windows.Close(job)
		_ = cmd.Process.Kill()
		return err
	}
	windows.Close(processHandle)
	if err := resumeProcessThreads(uint32(cmd.Process.Pid)); err != nil {
		windows.Close(job)
		_ = cmd.Process.Kill()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		_ = cmd.Wait()
		return err
	}
	p.cmd, p.stdin, p.job = cmd, stdin, job
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); p.copyOutput("stdout", stdout) }()
	go func() { defer readers.Done(); p.copyOutput("stderr", stderr) }()
	go func() {
		readers.Wait()
		err := cmd.Wait()
		result := exitResult(cmd.ProcessState)
		p.mu.Lock()
		p.result = result
		if _, ok := err.(*osExec.ExitError); !ok {
			p.waitErr = err
		}
		p.mu.Unlock()
		windows.Close(p.job)
		p.job = 0
		close(p.done)
	}()
	return nil
}

func resumeProcessThreads(processID uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.Close(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return err
	}
	resumed := false
	for {
		if entry.OwnerProcessID == processID {
			thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if openErr != nil {
				return openErr
			}
			previous, resumeErr := windows.ResumeThread(thread)
			windows.Close(thread)
			if resumeErr != nil || previous == ^uint32(0) {
				if resumeErr != nil {
					return resumeErr
				}
				return errors.New("resume suspended exec thread")
			}
			resumed = true
		}
		if err := windows.Thread32Next(snapshot, &entry); err != nil {
			if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				break
			}
			return err
		}
	}
	if !resumed {
		return errors.New("suspended exec thread not found")
	}
	return nil
}
func (p *pipeProcess) copyOutput(stream string, reader io.Reader) {
	buffer := make([]byte, p.config.ChunkBytes)
	for {
		n, err := reader.Read(buffer)
		if n > 0 && p.config.Output != nil {
			p.config.Output(stream, buffer[:n])
		}
		if err != nil {
			return
		}
	}
}
func (p *pipeProcess) Write(data []byte) (int, error) {
	if p.stdin == nil {
		return 0, ErrInvalid
	}
	return p.stdin.Write(data)
}
func (p *pipeProcess) CloseInput() error {
	var err error
	p.closeOnce.Do(func() {
		if p.stdin != nil {
			err = p.stdin.Close()
		}
	})
	return err
}
func (p *pipeProcess) Resize(pty.Dimensions) error { return ErrInvalid }
func (p *pipeProcess) Signal(signal pty.Signal) error {
	if p.cmd == nil || p.cmd.Process == nil {
		return ErrInvalid
	}
	if signal != pty.Interrupt && signal != pty.Terminate && signal != pty.Hangup && signal != pty.Kill {
		return ErrInvalid
	}
	err := p.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}
func (p *pipeProcess) Wait(ctx context.Context) (Result, error) {
	select {
	case <-p.done:
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.result, p.waitErr
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}
func (p *pipeProcess) Terminate(ctx context.Context, grace time.Duration) (Result, error) {
	select {
	case <-p.done:
		return p.Wait(context.Background())
	default:
	}
	if err := p.Signal(pty.Terminate); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return Result{}, err
	}
	graceCtx, cancel := context.WithTimeout(ctx, grace)
	result, err := p.Wait(graceCtx)
	cancel()
	if err == nil {
		_ = p.CloseInput()
		return result, nil
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	_ = p.Signal(pty.Kill)
	result, err = p.Wait(ctx)
	_ = p.CloseInput()
	return result, err
}

type ptyProcess struct {
	config     processConfig
	process    *pty.Process
	outputDone chan struct{}
}

func (p *ptyProcess) Start(context.Context) error {
	adapter, err := pty.NewAdapter(p.config.WorkspaceRoot)
	if err != nil {
		return err
	}
	environment := mergedEnvironment(p.config.BaseEnvironment, p.config.Request.Environment)
	path, err := lookPath(p.config.Request.Argv[0], environment)
	if err != nil {
		return ErrInvalid
	}
	process, err := adapter.Start(pty.Command{Path: path, Args: p.config.Request.Argv[1:], Env: environment, CWD: p.config.Request.CWD, Dimensions: p.config.Request.Dimensions})
	if err != nil {
		return err
	}
	p.process, p.outputDone = process, make(chan struct{})
	go func() {
		defer close(p.outputDone)
		buffer := make([]byte, p.config.ChunkBytes)
		for {
			n, readErr := process.Read(buffer)
			if n > 0 && p.config.Output != nil {
				p.config.Output("pty", buffer[:n])
			}
			if readErr != nil {
				return
			}
		}
	}()
	return nil
}
func (p *ptyProcess) Write(data []byte) (int, error) {
	if p.process == nil {
		return 0, ErrInvalid
	}
	return p.process.Write(data)
}
func (p *ptyProcess) CloseInput() error {
	if p.process == nil {
		return ErrInvalid
	}
	return p.process.CloseIO()
}
func (p *ptyProcess) Signal(signal pty.Signal) error {
	if p.process == nil {
		return ErrInvalid
	}
	return p.process.Signal(signal)
}
func (p *ptyProcess) Resize(dimensions pty.Dimensions) error {
	if p.process == nil {
		return ErrInvalid
	}
	return p.process.Resize(dimensions)
}
func (p *ptyProcess) Wait(ctx context.Context) (Result, error) {
	if p.process == nil {
		return Result{}, ErrInvalid
	}
	value, err := p.process.Wait(ctx)
	if err == nil {
		select {
		case <-p.outputDone:
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}
	return Result{Code: value.Code, Signal: value.Signal, ExitedAt: value.ExitedAt}, err
}
func (p *ptyProcess) Terminate(ctx context.Context, grace time.Duration) (Result, error) {
	if p.process == nil {
		return Result{}, ErrInvalid
	}
	value, err := p.process.Terminate(ctx, grace)
	if err == nil && p.outputDone != nil {
		select {
		case <-p.outputDone:
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}
	return Result{Code: value.Code, Signal: value.Signal, ExitedAt: value.ExitedAt}, err
}

func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.Close(job)
		return 0, err
	}
	return job, nil
}
func lookPath(command string, environment []string) (string, error) {
	if strings.ContainsAny(command, `/\\`) {
		return pty.ValidateProcessPolicy(command, nil, environment)
	}
	pathValue := ""
	for _, entry := range environment {
		if key, value, ok := strings.Cut(entry, "="); ok && strings.EqualFold(key, "PATH") {
			pathValue = value
			break
		}
	}
	if pathValue == "" {
		return "", ErrInvalid
	}
	for _, directory := range filepath.SplitList(pathValue) {
		if directory == "" || !filepath.IsAbs(directory) {
			continue
		}
		for _, extension := range []string{"", ".exe"} {
			if resolved, err := pty.ValidateProcessPolicy(filepath.Join(directory, command+extension), nil, environment); err == nil {
				return resolved, nil
			}
		}
	}
	return "", ErrInvalid
}
func exitResult(state *os.ProcessState) Result {
	result := Result{ExitedAt: time.Now().UTC()}
	if state == nil {
		result.Code = -1
	} else {
		result.Code = state.ExitCode()
	}
	return result
}
