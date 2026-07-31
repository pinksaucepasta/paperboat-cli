//go:build darwin || linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
)

type CoordinatorPreviewManager struct {
	Executable string
	StateRoot  string

	mu       sync.Mutex
	children map[string]*previewChild
}

type previewChild struct {
	command *exec.Cmd
	done    chan error
}

func (m *CoordinatorPreviewManager) Start(context.Context) error {
	return m.recover()
}

func (m *CoordinatorPreviewManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	children := make([]*previewChild, 0, len(m.children))
	for _, child := range m.children {
		children = append(children, child)
	}
	m.mu.Unlock()
	for _, child := range children {
		if child.command.Process != nil {
			_ = child.command.Process.Signal(os.Interrupt)
		}
	}
	var result error
	for _, child := range children {
		select {
		case err := <-child.done:
			if err != nil && !isExpectedPreviewExit(err) {
				result = errors.Join(result, err)
			}
		case <-ctx.Done():
			if child.command.Process != nil {
				_ = child.command.Process.Kill()
			}
			result = errors.Join(result, ctx.Err())
		}
	}
	return result
}

func (m *CoordinatorPreviewManager) Launch(ctx context.Context, input server.PreviewLaunchRequest) (preview.ControlRecord, error) {
	if !filepath.IsAbs(m.Executable) || !filepath.IsAbs(m.StateRoot) {
		return preview.ControlRecord{}, ErrProductionInvalid
	}
	var expiresAt *time.Time
	if !input.Indefinite {
		value := time.Now().UTC().Add(time.Duration(input.Duration) * time.Second)
		expiresAt = &value
	}
	descriptorPath, err := writeCoordinatorPreviewDescriptor(m.StateRoot, input.Name, input.Port, expiresAt, input.Indefinite)
	if err != nil {
		return preview.ControlRecord{}, err
	}
	command, ready, logFile, err := previewProcess(m.Executable, m.StateRoot, descriptorPath, PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: input.Name, Port: input.Port, Indefinite: input.Indefinite, ExpiresAt: expiresAt}, true)
	if err != nil {
		_ = os.Remove(descriptorPath)
		return preview.ControlRecord{}, err
	}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		_ = os.Remove(descriptorPath)
		return preview.ControlRecord{}, err
	}
	child := m.track(descriptorPath, command)
	_ = logFile.Close()
	result := make(chan struct {
		record preview.ControlRecord
		err    error
	}, 1)
	go func() {
		var value struct {
			record preview.ControlRecord
			err    error
		}
		value.err = json.NewDecoder(io.LimitReader(ready, 64<<10)).Decode(&value.record)
		result <- value
	}()
	select {
	case value := <-result:
		if value.err != nil || value.record.URL == "" {
			_ = command.Process.Kill()
			<-child.done
			return preview.ControlRecord{}, errors.New("preview runner failed before registration")
		}
		return value.record, nil
	case <-ctx.Done():
		_ = command.Process.Kill()
		<-child.done
		return preview.ControlRecord{}, ctx.Err()
	}
}

func (m *CoordinatorPreviewManager) recover() error {
	if !filepath.IsAbs(m.Executable) || !filepath.IsAbs(m.StateRoot) {
		return ErrProductionInvalid
	}
	directory := filepath.Join(m.StateRoot, "previews", "active")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var result error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		descriptor, readErr := readPreviewRuntimeDescriptor(path)
		if readErr != nil {
			result = errors.Join(result, fmt.Errorf("read preview descriptor %s: %w", entry.Name(), readErr))
			continue
		}
		if descriptor.ServiceDefinition != "" {
			continue
		}
		if descriptor.ExpiresAt != nil && !descriptor.ExpiresAt.After(now) {
			_ = os.Remove(path)
			continue
		}
		m.mu.Lock()
		_, alreadyRunning := m.children[path]
		m.mu.Unlock()
		if alreadyRunning {
			continue
		}
		command, _, logFile, commandErr := previewProcess(m.Executable, m.StateRoot, path, descriptor, false)
		if commandErr != nil {
			result = errors.Join(result, commandErr)
			continue
		}
		if err := command.Start(); err != nil {
			_ = logFile.Close()
			result = errors.Join(result, err)
			continue
		}
		_ = logFile.Close()
		m.track(path, command)
	}
	return result
}

func (m *CoordinatorPreviewManager) track(path string, command *exec.Cmd) *previewChild {
	child := &previewChild{command: command, done: make(chan error, 1)}
	m.mu.Lock()
	if m.children == nil {
		m.children = make(map[string]*previewChild)
	}
	m.children[path] = child
	m.mu.Unlock()
	go func() {
		child.done <- command.Wait()
		close(child.done)
		m.mu.Lock()
		if m.children[path] == child {
			delete(m.children, path)
		}
		m.mu.Unlock()
	}()
	return child
}

func isExpectedPreviewExit(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

func writeCoordinatorPreviewDescriptor(stateRoot, name string, port uint16, expiresAt *time.Time, indefinite bool) (string, error) {
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	if existing, err := readPreviewRuntimeDescriptor(path); err == nil && (existing.Indefinite || existing.ExpiresAt != nil && existing.ExpiresAt.After(time.Now().UTC())) {
		return "", ErrPreviewAlreadyActive
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: name, Port: port, Indefinite: indefinite, ExpiresAt: expiresAt}
	return path, writePreviewRuntimeDescriptor(path, descriptor)
}

func previewProcess(executable, stateRoot, descriptorPath string, descriptor PreviewRuntimeDescriptor, captureReady bool) (*exec.Cmd, io.ReadCloser, *os.File, error) {
	args := []string{"__runtime-preview", "--state-root", stateRoot, "--name", descriptor.Name, "--port", strconv.Itoa(int(descriptor.Port)), "--descriptor", descriptorPath}
	if descriptor.Indefinite {
		args = append(args, "--indefinite")
	} else {
		args = append(args, "--expires-at", descriptor.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	command := exec.Command(executable, args...)
	var ready io.ReadCloser
	var err error
	if captureReady {
		ready, err = command.StdoutPipe()
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		command.Stdout = io.Discard
	}
	logRoot := filepath.Join(stateRoot, "previews", "logs")
	if err := os.MkdirAll(logRoot, 0o700); err != nil {
		return nil, nil, nil, err
	}
	logFile, err := os.OpenFile(filepath.Join(logRoot, descriptor.Name+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, nil, err
	}
	command.Stderr = logFile
	return command, ready, logFile, nil
}
