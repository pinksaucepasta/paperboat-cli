//go:build darwin || linux

package workerupdate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

// ExecStarter starts only the fixed Paperboat worker entry point. The runtime
// artifact, socket, user identity, API range, and sealed capability all come
// from Manager; there is no user-controlled command, argument, or environment
// surface.
type ExecStarter struct{}

func (ExecStarter) Start(ctx context.Context, request StartRequest) (Worker, error) {
	if request.Executable == "" || request.WorkerID == "" || request.UID <= 0 || request.GID < 0 || request.HostdEndpoint == "" || len(request.Capability) != 32 || !request.MutationsDisabled {
		return nil, ErrInvalidConfig
	}
	if os.Geteuid() != 0 && request.UID != os.Geteuid() {
		return nil, ErrInvalidConfig
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	controlReader, controlWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}
	command := exec.CommandContext(ctx, request.Executable,
		"__runtime-worker", "--socket", request.HostdEndpoint, "--token-fd", "3",
		"--worker-id", request.WorkerID, "--version", request.Release.Version,
		"--api-min", strconv.FormatUint(uint64(request.Release.HostdAPIMin), 10),
		"--api-max", strconv.FormatUint(uint64(request.Release.HostdAPIMax), 10), "--wait-activation")
	command.ExtraFiles = []*os.File{reader}
	command.Stdin = controlReader
	stdout, err := command.StdoutPipe()
	if err != nil {
		reader.Close()
		writer.Close()
		controlReader.Close()
		controlWriter.Close()
		return nil, err
	}
	command.Stderr = io.Discard
	if os.Geteuid() == 0 {
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(request.UID), Gid: uint32(request.GID)}}
	}
	if err := command.Start(); err != nil {
		reader.Close()
		writer.Close()
		controlReader.Close()
		controlWriter.Close()
		return nil, err
	}
	reader.Close()
	controlReader.Close()
	if _, err := writer.Write(request.Capability); err != nil {
		writer.Close()
		controlWriter.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		controlWriter.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, err
	}
	return &execWorker{command: command, control: controlWriter, lines: bufio.NewReader(io.LimitReader(stdout, 128)), workerID: request.WorkerID}, nil
}

// execWorker uses a private stdin pipe for exactly one fixed activation word.
// Capability bytes travel only through the inherited descriptor, so they can
// never be confused with an activation request.
type execWorker struct {
	command  *exec.Cmd
	control  io.WriteCloser
	lines    *bufio.Reader
	workerID string
	mu       sync.Mutex
	ready    hostdproto.Status
}

func (w *execWorker) Ready(context.Context) (hostdproto.Status, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ready.Epoch != 0 {
		return w.ready, nil
	}
	line, err := readWorkerLine(w.lines)
	if err != nil {
		return hostdproto.Status{}, err
	}
	status, err := parseWorkerStatus(line, "ready", w.workerID)
	if err == nil {
		w.ready = status
	}
	return status, err
}

func (w *execWorker) Activate(context.Context) (hostdproto.Status, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ready.Epoch == 0 || w.control == nil {
		return hostdproto.Status{}, errors.New("worker is not ready")
	}
	if _, err := io.WriteString(w.control, "activate\n"); err != nil {
		return hostdproto.Status{}, err
	}
	if err := w.control.Close(); err != nil {
		return hostdproto.Status{}, err
	}
	w.control = nil
	line, err := readWorkerLine(w.lines)
	if err != nil {
		return hostdproto.Status{}, err
	}
	status, err := parseWorkerStatus(line, "active", w.workerID)
	if err != nil || status.Epoch != w.ready.Epoch || status.APIVersion != w.ready.APIVersion {
		return hostdproto.Status{}, ErrInvalidRelease
	}
	return status, nil
}
func (w *execWorker) Stop(ctx context.Context) error {
	if w.command == nil || w.command.Process == nil {
		return nil
	}
	_ = w.command.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- w.command.Wait() }()
	select {
	case <-ctx.Done():
		_ = w.command.Process.Kill()
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
		return nil
	case <-time.After(5 * time.Second):
		_ = w.command.Process.Kill()
		return <-done
	}
}

func parseWorkerStatus(line, state, workerID string) (hostdproto.Status, error) {
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[0] != state || workerID == "" {
		return hostdproto.Status{}, ErrInvalidRelease
	}
	epoch, epochErr := strconv.ParseUint(parts[1], 10, 64)
	api, apiErr := strconv.ParseUint(parts[2], 10, 16)
	if epochErr != nil || apiErr != nil || epoch == 0 || api == 0 {
		return hostdproto.Status{}, ErrInvalidRelease
	}
	hostState := hostdproto.StateCandidate
	if state == "active" {
		hostState = hostdproto.StateActive
	}
	return hostdproto.Status{State: hostState, WorkerID: workerID, Epoch: epoch, APIVersion: uint16(api)}, nil
}

func readWorkerLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > 64 {
		return "", fmt.Errorf("worker lifecycle response exceeds limit")
	}
	return line, nil
}
