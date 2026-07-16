package connect

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrInvalidRuntime = errors.New("connector runtime configuration is invalid")

type RuntimeProcess struct {
	Name, Executable string
	Arguments        []string
	Environment      []string
}

type Child interface {
	Wait() error
	Stop() error
}
type Runner interface {
	Start(context.Context, RuntimeProcess) (Child, error)
}

type Supervisor struct {
	Processes       []RuntimeProcess
	Runner          Runner
	RestartBackoff  time.Duration
	MaxRestartDelay time.Duration
}

func (s Supervisor) Run(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	backoff := s.RestartBackoff
	if backoff <= 0 {
		backoff = time.Second
	}
	maxDelay := s.MaxRestartDelay
	if maxDelay < backoff {
		maxDelay = 30 * time.Second
	}
	for {
		err := s.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			err = errors.New("connector runtime exited unexpectedly")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxDelay {
			backoff = maxDelay
		}
	}
}

func (s Supervisor) validate() error {
	if len(s.Processes) == 0 || s.Runner == nil {
		return ErrInvalidRuntime
	}
	seen := map[string]bool{}
	for _, process := range s.Processes {
		if strings.TrimSpace(process.Name) == "" || !filepath.IsAbs(process.Executable) || seen[process.Name] {
			return ErrInvalidRuntime
		}
		seen[process.Name] = true
	}
	return nil
}

func (s Supervisor) runOnce(ctx context.Context) error {
	children := make([]Child, 0, len(s.Processes))
	for _, process := range s.Processes {
		child, err := s.Runner.Start(ctx, process)
		if err != nil {
			stopAll(children)
			return fmt.Errorf("start %s: %w", process.Name, err)
		}
		children = append(children, child)
	}
	results := make(chan error, len(children))
	for _, child := range children {
		go func(child Child) { results <- child.Wait() }(child)
	}
	select {
	case <-ctx.Done():
		stopAll(children)
		<-results
		return nil
	case err := <-results:
		stopAll(children)
		return err
	}
}

func stopAll(children []Child) {
	var wg sync.WaitGroup
	for _, child := range children {
		wg.Add(1)
		go func(child Child) { defer wg.Done(); _ = child.Stop() }(child)
	}
	wg.Wait()
}

type ExecRunner struct{}
type execChild struct{ command *exec.Cmd }

func (ExecRunner) Start(ctx context.Context, process RuntimeProcess) (Child, error) {
	command := exec.CommandContext(ctx, process.Executable, process.Arguments...)
	command.Env = append(command.Environ(), process.Environment...)
	if err := command.Start(); err != nil {
		return nil, err
	}
	return execChild{command: command}, nil
}
func (c execChild) Wait() error { return c.command.Wait() }
func (c execChild) Stop() error {
	if c.command.Process == nil {
		return nil
	}
	return c.command.Process.Kill()
}
