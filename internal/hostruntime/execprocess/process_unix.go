//go:build darwin || linux

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

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
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
	cmd.Args[0] = p.config.Request.Argv[0]
	cmd.Dir, cmd.Env = p.config.Request.CWD, environment
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		return err
	}
	p.cmd, p.stdin = cmd, stdin
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
		close(p.done)
	}()
	return nil
}

func (p *pipeProcess) copyOutput(stream string, reader io.Reader) {
	buffer := make([]byte, p.config.ChunkBytes)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
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
	native, ok := nativeSignal(signal)
	if !ok || p.cmd == nil || p.cmd.Process == nil {
		return ErrInvalid
	}
	if err := syscall.Kill(-p.cmd.Process.Pid, native); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
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
	if err := p.Signal(pty.Terminate); err != nil {
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
	if err := p.Signal(pty.Kill); err != nil {
		return Result{}, err
	}
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
	p.process = process
	p.outputDone = make(chan struct{})
	go func() {
		defer close(p.outputDone)
		buffer := make([]byte, p.config.ChunkBytes)
		for {
			n, readErr := process.Read(buffer)
			if n > 0 {
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

func lookPath(command string, environment []string) (string, error) {
	if strings.ContainsRune(command, '/') {
		return pty.ValidateProcessPolicy(command, nil, environment)
	}
	pathValue := ""
	for _, entry := range environment {
		if key, value, ok := strings.Cut(entry, "="); ok && key == "PATH" {
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
		candidate := filepath.Join(directory, command)
		if resolved, err := pty.ValidateProcessPolicy(candidate, nil, environment); err == nil {
			return resolved, nil
		}
	}
	return "", ErrInvalid
}

func exitResult(state *os.ProcessState) Result {
	result := Result{ExitedAt: time.Now().UTC()}
	if status, ok := state.Sys().(syscall.WaitStatus); ok {
		if status.Signaled() {
			result.Code, result.Signal = 128+int(status.Signal()), status.Signal().String()
		} else {
			result.Code = status.ExitStatus()
		}
	} else if state.Success() {
		result.Code = 0
	} else {
		result.Code = -1
	}
	return result
}

func nativeSignal(signal pty.Signal) (syscall.Signal, bool) {
	switch signal {
	case pty.Interrupt:
		return syscall.SIGINT, true
	case pty.Terminate:
		return syscall.SIGTERM, true
	case pty.Hangup:
		return syscall.SIGHUP, true
	case pty.Kill:
		return syscall.SIGKILL, true
	default:
		return 0, false
	}
}
